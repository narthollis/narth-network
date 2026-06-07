use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ipv4::prefix_to_mask;
use crate::runtime::address_table::AddressTable;
use crate::runtime::interface::context::InterfaceContext;
use crate::runtime::interface::l2_ethernet::{ArpState, ArpTable};
use crate::runtime::interface::l4_managers::Managers;
use crate::runtime::interface::{Error, InterfaceControlMessage, ResultSender, l2_ethernet};
use crate::runtime::route_table::RouteTable;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::sync::mpsc;
use tracing::{error, info};

pub struct InterfaceWorker {
    control_rx: mpsc::Receiver<InterfaceControlMessage>,
    network_rx: super::super::channel::NetworkRecvReceiver,

    pub(super) ipv4_pending_addresses: Vec<(Ipv4Addr, Ipv4Addr, ResultSender<()>)>,

    pub(super) context: InterfaceContext,
    managers: Managers,
}

impl InterfaceWorker {
    pub(super) const MAX_IPV4_PENDING_BUFFER_SIZE: usize = 5;

    pub(super) fn new(
        control_rx: mpsc::Receiver<InterfaceControlMessage>,
        network_tx: super::super::channel::NetworkSender,
        network_rx: super::super::channel::NetworkRecvReceiver,
        mtu: usize,
        mac_addr: MacAddr,
    ) -> Self {
        Self {
            control_rx,
            network_rx,

            ipv4_pending_addresses: Vec::default(),
            context: InterfaceContext {
                mac_addr,
                mtu,

                network_tx,
                arp_table: ArpTable::default(),
                ipv4_addresses: AddressTable::default(),
                ipv4_route_table: RouteTable::default(),
                ipv4_send_buffer: HashMap::default(),
            },
            managers: Managers::default(),
        }
    }

    pub fn run(&mut self) {
        info!(
            "Running interface {interface} worker",
            interface = self.context.mac_addr
        );

        loop {
            if !self.perform_control() {
                error!("Interface {} control closed", self.context.mac_addr);
                break;
            }
            loop {
                use ringbuf::traits::Consumer;

                match self.network_rx.try_pop() {
                    Some(super::super::channel::NetworkRecvPayload::Packet(bytes)) => {
                        l2_ethernet::EthernetHandler::recv(
                            &mut self.context,
                            &mut self.managers,
                            bytes,
                        );
                    }
                    None => {
                        break;
                    }
                }
            }

            let deadline = self.perform_timers();

            std::thread::park_timeout(
                deadline.saturating_duration_since(std::time::Instant::now()),
            );
        }
        error!("Interface {} worker stopped", self.context.mac_addr);
    }

    fn perform_control(&mut self) -> bool {
        while let Ok(msg) = self.control_rx.try_recv() {
            match msg {
                InterfaceControlMessage::IPv4AddressAdd(addr, prefix, reply) => {
                    self.handle_ipv4_address_add(addr, prefix, reply);
                }
                InterfaceControlMessage::IPv4AddressRemove(addr) => {
                    self.handle_ipv4_address_remove(addr);
                }
                InterfaceControlMessage::IPv4RouteAdd {
                    target,
                    target_mask,
                    next_hop,
                    src,
                    reply,
                } => {
                    _ = reply.send(self.handle_ipv4_route_add(target, target_mask, next_hop, src));
                }
                InterfaceControlMessage::IPv4RouteRemove() => todo!(),
                InterfaceControlMessage::Ping {
                    target,
                    count,
                    interval,
                    reply,
                } => _ = reply.send(Ok(self.managers.ping_manager.ping(target, count, interval))),
                InterfaceControlMessage::Stop() => {
                    return false;
                }
            }
        }

        if !self.ipv4_pending_addresses.is_empty() {
            for i in (0..self.ipv4_pending_addresses.len()).rev() {
                match self
                    .context
                    .arp_table
                    .request(self.ipv4_pending_addresses[i].0, Ipv4Addr::UNSPECIFIED)
                {
                    ArpState::PendingWait { .. } => {}
                    ArpState::PendingRetry { .. }
                    | ArpState::ResolvedStale(_)
                    | ArpState::Restart => {
                        if let Err(err) = l2_ethernet::EthernetHandler::send_arp_request(
                            &mut self.context,
                            self.ipv4_pending_addresses[i].0,
                            Ipv4Addr::UNSPECIFIED,
                        ) {
                            let (_, _, reply) = self.ipv4_pending_addresses.remove(i);
                            _ = reply.send(Err(Error::AddressCheckFailed(err)));
                        }
                    }
                    ArpState::Timeout => {
                        let (addr, mask, reply) = self.ipv4_pending_addresses.remove(i);
                        self.context.ipv4_addresses.insert(addr, mask);
                        self.context.ipv4_route_table.insert_or_update(
                            addr & mask,
                            mask,
                            addr,
                            None,
                        );
                        _ = reply.send(Ok(()));
                        _ = l2_ethernet::EthernetHandler::send_gratuitous_arp(
                            &mut self.context,
                            addr,
                        );
                    }
                    ArpState::Resolved(_) => {
                        let (_, _, reply) = self.ipv4_pending_addresses.remove(i);
                        _ = reply.send(Err(Error::AddressInUse));
                    }
                }
            }
        }

        true
    }

    fn handle_ipv4_address_add(&mut self, addr: Ipv4Addr, prefix: u8, reply: ResultSender<()>) {
        if let Err(err) = l2_ethernet::EthernetHandler::send_arp_request(
            &mut self.context,
            addr,
            Ipv4Addr::UNSPECIFIED,
        ) {
            _ = reply.send(Err(Error::AddressCheckFailed(err)));

            return;
        }

        self.ipv4_pending_addresses
            .push((addr, prefix_to_mask(prefix), reply));
    }

    fn handle_ipv4_address_remove(&mut self, addr: Ipv4Addr) {
        // iterate in reverse order so we don't end up with shifting index shenanigans
        for i in (0..self.ipv4_pending_addresses.len()).rev() {
            if self.ipv4_pending_addresses[i].0 == addr {
                let (_, _, reply) = self.ipv4_pending_addresses.remove(i);
                _ = reply.send(Err(Error::AddressRemoved));
            }
        }

        self.context
            .ipv4_route_table
            .remove_matching(|x| x.source == addr);
        self.context.ipv4_addresses.remove(&addr);
    }

    fn handle_ipv4_route_add(
        &mut self,
        target: Ipv4Addr,
        target_mask: Ipv4Addr,
        next_hop: Ipv4Addr,
        src: Option<Ipv4Addr>,
    ) -> crate::runtime::interface::Result<()> {
        let src = src
            .or_else(|| {
                self.context
                    .ipv4_addresses
                    .first_with_subnet_containing(&next_hop)
            })
            .ok_or(Error::RouteNextHopUnreachable())
            .and_then(|src| {
                if self.context.ipv4_addresses.contains(&src) {
                    Ok(src)
                } else {
                    Err(Error::RouteUnknownSource())
                }
            })?;

        self.context
            .ipv4_route_table
            .insert_or_update(target, target_mask, src, Some(next_hop));

        Ok(())
    }

    fn perform_timers(&mut self) -> std::time::Instant {
        let arp_deadline =
            l2_ethernet::EthernetHandler::perform_arp_timers(&mut self.context, &mut self.managers);
        let icmp_deadline = self.managers.ping_manager.perform_timers(&mut self.context);

        [arp_deadline, icmp_deadline]
            .iter()
            .flatten()
            .min()
            .map_or_else(
                || std::time::Instant::now().add(std::time::Duration::from_secs(1)),
                |x| *x,
            )
    }
}

impl std::fmt::Debug for InterfaceWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceWorker")
            .field("control_rx", &self.control_rx)
            .field("network_rx", &"RingBufConsumer<NetworkRecvReceiver>")
            .field("ipv4_pending_addresses", &self.ipv4_pending_addresses)
            .field("context", &self.context)
            .field("managers", &self.managers)
            .finish()
    }
}

impl Drop for InterfaceWorker {
    fn drop(&mut self) {
        // TODO consider if we need to pull this onto the general network control channel when we introduce that
        self.context
            .network_tx
            .try_send(super::super::channel::NetworkSendPayload::Closed(
                self.context.mac_addr,
            ))
            .expect("send closed");
    }
}

impl std::fmt::Display for InterfaceWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InterfaceWorker({})", self.context.mac_addr)
    }
}
