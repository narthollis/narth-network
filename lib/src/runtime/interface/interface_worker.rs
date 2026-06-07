use crate::common::WriteToBuffer;
use crate::protocols::arp::{ArpMessage, ArpState, ArpTable, Operation};
use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use crate::protocols::ipv4::icmp::{
    ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH, ICMPMessage, ICMPMessageTypes,
};
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header, prefix_to_mask};
use crate::runtime::address_table::AddressTable;
use crate::runtime::interface::AsyncSendError::LocalSendError;
use crate::runtime::interface::SendError::ArpTimeout;
use crate::runtime::interface::sender_context::SenderContext;
use crate::runtime::interface::{AsyncSendError, Error, InterfaceControlMessage, ResultSender};
use crate::runtime::route_table::RouteTable;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::sync::mpsc;
use tracing::{debug, error, info, trace, trace_span, warn};

pub struct InterfaceWorker {
    control_rx: mpsc::Receiver<InterfaceControlMessage>,

    // network_tx: super::common::NetworkSender,
    network_rx: super::super::common::NetworkRecvReceiver,

    mtu: usize,
    mac_addr: MacAddr,

    ping_manager: super::super::ping::PingManager,

    pub(super) ipv4_addresses: AddressTable<Ipv4Addr>,
    pub(super) ipv4_pending_addresses: Vec<(Ipv4Addr, Ipv4Addr, ResultSender<()>)>,
    pub(super) sender_context: SenderContext,
}

impl InterfaceWorker {
    pub(super) const MAX_IPV4_PENDING_BUFFER_SIZE: usize = 5;

    pub(super) fn new(
        control_rx: mpsc::Receiver<InterfaceControlMessage>,
        network_tx: super::super::common::NetworkSender,
        network_rx: super::super::common::NetworkRecvReceiver,
        mtu: usize,
        mac_addr: MacAddr,
    ) -> Self {
        Self {
            control_rx,
            // network_tx,
            network_rx,
            mtu,
            mac_addr,

            ping_manager: super::super::ping::PingManager::default(),

            // arp_table: ArpTable::default(),
            ipv4_addresses: AddressTable::default(),
            // ipv4_route_table: RouteTable::default(),
            ipv4_pending_addresses: Vec::default(),
            // ipv4_send_buffer: HashMap::default(),
            sender_context: SenderContext {
                mac_addr,
                mtu,

                network_tx,
                arp_table: ArpTable::default(),
                ipv4_route_table: RouteTable::default(),
                ipv4_send_buffer: HashMap::default(),
            },
        }
    }

    pub fn run(&mut self) {
        info!(
            "Running interface {interface} worker",
            interface = self.mac_addr
        );

        loop {
            if !self.perform_control() {
                error!("Interface {} control closed", self.mac_addr);
                break;
            }
            loop {
                use ringbuf::traits::Consumer;

                match self.network_rx.try_pop() {
                    Some(super::super::common::NetworkRecvPayload::Packet(bytes)) => {
                        self.recv(&bytes);
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
        error!("Interface {} worker stopped", self.mac_addr);
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
                } => _ = reply.send(Ok(self.ping_manager.ping(target, count, interval))),
                InterfaceControlMessage::Stop() => {
                    return false;
                }
            }
        }

        if !self.ipv4_pending_addresses.is_empty() {
            use crate::protocols::arp::ArpState;

            for i in (0..self.ipv4_pending_addresses.len()).rev() {
                match self
                    .sender_context
                    .arp_table
                    .request(self.ipv4_pending_addresses[i].0, Ipv4Addr::UNSPECIFIED)
                {
                    ArpState::PendingWait { .. } => {}
                    ArpState::PendingRetry { .. }
                    | ArpState::ResolvedStale(_)
                    | ArpState::Restart => {
                        if let Err(err) = self.sender_context.send_arp_request(
                            self.ipv4_pending_addresses[i].0,
                            Ipv4Addr::UNSPECIFIED,
                        ) {
                            let (_, _, reply) = self.ipv4_pending_addresses.remove(i);
                            _ = reply.send(Err(Error::AddressCheckFailed(err)));
                        }
                    }
                    ArpState::Timeout => {
                        let (addr, mask, reply) = self.ipv4_pending_addresses.remove(i);
                        self.ipv4_addresses.insert(addr, mask);
                        self.sender_context.ipv4_route_table.insert_or_update(
                            addr & mask,
                            mask,
                            addr,
                            None,
                        );
                        _ = reply.send(Ok(()));
                        _ = self.sender_context.send_gratuitous_arp(addr);
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
        if let Err(err) = self
            .sender_context
            .send_arp_request(addr, Ipv4Addr::UNSPECIFIED)
        {
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

        self.sender_context
            .ipv4_route_table
            .remove_matching(|x| x.source == addr);
        self.ipv4_addresses.remove(&addr);
    }

    fn handle_ipv4_route_add(
        &mut self,
        target: Ipv4Addr,
        target_mask: Ipv4Addr,
        next_hop: Ipv4Addr,
        src: Option<Ipv4Addr>,
    ) -> crate::runtime::interface::Result<()> {
        let src = src
            .or_else(|| self.ipv4_addresses.first_with_subnet_containing(&next_hop))
            .ok_or(Error::RouteNextHopUnreachable())
            .and_then(|src| {
                if self.ipv4_addresses.contains(&src) {
                    Ok(src)
                } else {
                    Err(Error::RouteUnknownSource())
                }
            })?;

        self.sender_context.ipv4_route_table.insert_or_update(
            target,
            target_mask,
            src,
            Some(next_hop),
        );

        Ok(())
    }

    fn perform_timers(&mut self) -> std::time::Instant {
        let arp_deadline = self.perform_arp_timers();
        let icmp_deadline = self.ping_manager.perform_timers(&mut self.sender_context);

        [arp_deadline, icmp_deadline]
            .iter()
            .flatten()
            .min()
            .map_or_else(
                || std::time::Instant::now().add(std::time::Duration::from_secs(1)),
                |x| *x,
            )
    }

    fn perform_arp_timers(&mut self) -> Option<std::time::Instant> {
        let mut deadline: Option<std::time::Instant> = None;

        for (ip, source) in self.sender_context.arp_table.pending() {
            match self.sender_context.arp_table.request(ip, source) {
                ArpState::PendingWait {
                    deadline: request_deadline,
                } => {
                    deadline = deadline
                        .map(|dl| dl.min(request_deadline))
                        .or(Some(request_deadline));
                }
                ArpState::PendingRetry { source } => {
                    _ = self.sender_context.send_arp_request(ip, source);
                }
                // Look, I don't quite know how we would hit ResolvedStale here, but...
                ArpState::Resolved(mac) | ArpState::ResolvedStale(mac) => {
                    self.dequeue_pending_ipv4(mac, ip);
                    // TODO Whatever else is needed now the address has been resovled - not sure what that is
                }
                // Restart is when the Timeout has gone stale or the Resolved has gone through stale out the other side
                ArpState::Timeout | ArpState::Restart => {
                    if let Some(queue) = self.sender_context.ipv4_send_buffer.remove(&ip) {
                        for (ipv4header, payload) in queue {
                            self.forward_async_error(LocalSendError {
                                error: ArpTimeout,
                                ipv4header,
                                datagram: payload[..ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH]
                                    .try_into()
                                    .unwrap_or([0u8; 8]),
                            });
                        }
                    }
                }
            }
        }

        deadline
    }

    fn recv(&mut self, frame: &bytes::Bytes) {
        let ethernet_header = match crate::protocols::ethernet::EthernetHeader::from_bytes(&frame) {
            Ok(ethernet_header) => ethernet_header,
            Err(e) => {
                debug!("failed to parse ethernet header: {}", e);
                return;
            }
        };
        let ethernet_payload = frame.slice(ethernet_header.encoded_length()..);

        trace_span!(
            "recv",
            ethernet_source = ethernet_header.source_address().to_string(),
            ethernet_destination = ethernet_header.destination_address().to_string(),
        );
        trace!("Incoming Ethernet header: {:?}", ethernet_header);

        match ethernet_header.ether_type() {
            EtherType::ARP => self.recv_arp(ethernet_payload),
            EtherType::IPv4 => self.recv_ipv4(ethernet_header, &ethernet_payload),
            EtherType::IPv6 => {
                // TODO
            }
            t => debug!("unsupported ethernet type: {:?}", t),
        }
    }

    fn recv_arp(&mut self, bytes: bytes::Bytes) {
        let arp = match ArpMessage::from_bytes(&bytes) {
            Ok(arp) => arp,
            Err(e) => {
                debug!("failed to parse arp message: {}", e);
                return;
            }
        };
        trace!("Incoming ARP: {:?}", arp);

        // https://datatracker.ietf.org/doc/rfc826/ Packet Reception

        // Update the table ONLY IF the sender protocol already exits
        let mut merged = self
            .sender_context
            .arp_table
            .update_only(arp.source_mac(), arp.source_addr());

        if self.ipv4_addresses.contains(&arp.target_addr()) {
            if !merged {
                self.sender_context
                    .arp_table
                    .update_or_insert(arp.source_mac(), arp.source_addr());
                merged = true;
            }

            if arp.operation() == Operation::Request {
                let reply = arp.reply(self.mac_addr, arp.target_addr());
                if let Err(err) =
                    self.sender_context
                        .send_ethernet(reply.target_mac(), EtherType::ARP, &reply)
                {
                    // Sending the ARP Response - if this doesn't work not much we can do
                    error!("Failed to send ARP reply: {}", err);
                }
            }
        }

        if merged {
            self.dequeue_pending_ipv4(arp.source_mac(), arp.source_addr());
        }
    }

    fn recv_ipv4(&mut self, ethernet: EthernetHeader, bytes: &bytes::Bytes) {
        let ip = match IPv4Header::from_bytes(&bytes) {
            Ok(ip) => ip,
            Err(e) => {
                debug!("failed to parse ipv4 header: {}", e);
                return;
            }
        };
        if ip.is_fragmented() {
            trace!("dropping fragmented IPv4");
            return;
        }

        let payload = &bytes.slice(ip.encoded_length()..ip.total_length());

        trace_span!(
            "recv ipv4",
            ipv4_source = ip.source_address().to_string(),
            ipv4_destination = ip.destination_address().to_string()
        );
        trace!("Incoming IPv4 header: {:?}", ip);

        let merged = self
            .sender_context
            .arp_table
            .update_or_insert(ethernet.source_address(), ip.source_address());
        let source_address = ip.source_address();

        match ip.protocol() {
            IPProtocolTypes::ICMP => self.recv_ipv4_icmp(ip, payload),
            IPProtocolTypes::UDP => {
                // todo udp
                // self.udp_manager.recv_ipv4(ip.source(), ip.destination(), payload);
            }
            IPProtocolTypes::TCP => {
                // todo tcp
            }
            IPProtocolTypes::Other(protocol) => {
                info!("Received IPv4 message for {protocol}");
                // protocol we don't care about so drop it
            }
        };

        if merged {
            self.dequeue_pending_ipv4(ethernet.source_address(), source_address);
        }
    }

    fn recv_ipv4_icmp(&mut self, ipv4_header: IPv4Header, payload: &bytes::Bytes) {
        let icmp = match ICMPMessage::from_bytes(payload) {
            Ok(icmp) => icmp,
            Err(e) => {
                debug!("failed to parse icmp message: {}", e);
                return;
            }
        };
        trace!("Incoming IPv4 ICMP: {:?}", icmp);

        match &icmp.message {
            ICMPMessageTypes::Echo(echo) => {
                let echo_reply = ICMPMessage::echo_reply(echo);

                // We don't really care if we fail to send the echo reply
                _ = self.sender_context.send_ipv4(
                    ipv4_header.source_address(),
                    ipv4_header.destination_address(),
                    IPProtocolTypes::ICMP,
                    &echo_reply,
                );
            }
            ICMPMessageTypes::EchoReply(reply) => {
                self.ping_manager.on_echo_reply(ipv4_header, reply);
            }
            ICMPMessageTypes::DestinationUnreachable(m) => {
                self.forward_async_error(AsyncSendError::ICMPUnreachable(*m));
            }
            _ => {
                // TODO we need to parse the identifying data out of the control message's data and then
                // forward it to the protocol manager
                eprintln!("CONTROL MESSAGE: {icmp:?}");
            }
        }
    }

    fn forward_async_error(&mut self, error: AsyncSendError) {
        let (header, datagram) = match &error {
            AsyncSendError::LocalSendError {
                ipv4header,
                datagram,
                ..
            } => (ipv4header, datagram),
            AsyncSendError::ICMPUnreachable(m) => (&m.ipv4header, &m.datagram),
        };

        match header.protocol() {
            IPProtocolTypes::ICMP => {
                let kind = datagram[0];
                let code = datagram[1];
                // let checksum = [unreachable.datagram[2], unreachable.datagram[3]];

                if kind == 8 {
                    self.ping_manager.on_async_send_error(error);
                } else {
                    warn!("ICMP unreachable for ICMP: {kind}/{code}");
                }
            }
            _ => {
                error!(
                    "Interface={interface} - Error={error:?}",
                    interface = self.mac_addr,
                    error = &error
                );
            }
        }
    }

    fn dequeue_pending_ipv4(&mut self, mac: MacAddr, ipv4addr: Ipv4Addr) {
        if let Some(queue) = self.sender_context.ipv4_send_buffer.remove(&ipv4addr) {
            trace!(
                "resolved {} draining {} pending messages",
                ipv4addr,
                queue.len()
            );

            for pending in queue {
                if let Err(error) =
                    self.sender_context
                        .send_ethernet(mac, EtherType::IPv4, &pending)
                {
                    self.forward_async_error(AsyncSendError::LocalSendError {
                        error,
                        ipv4header: pending.0,
                        // We should not have accepted an IPv4 message <8 bytes but hey
                        datagram: pending.1[0..8].try_into().unwrap_or([0u8; 8]),
                    });
                }
            }
        }
    }
}

impl std::fmt::Debug for InterfaceWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceWorker")
            .field("mtu", &self.mtu)
            .field("mac_addr", &self.mac_addr)
            .field("ping_manager", &self.ping_manager)
            .field("ipv4_addresses", &self.ipv4_addresses)
            .field("sender_context", &self.sender_context)
            .finish_non_exhaustive()
    }
}

impl Drop for InterfaceWorker {
    fn drop(&mut self) {
        // TODO consider if we need to pull this onto the general network control channel when we introduce that
        self.sender_context
            .network_tx
            .try_send(super::super::common::NetworkSendPayload::Closed(
                self.mac_addr,
            ))
            .expect("send closed");
    }
}

impl std::fmt::Display for InterfaceWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InterfaceWorker({})", self.mac_addr)
    }
}
