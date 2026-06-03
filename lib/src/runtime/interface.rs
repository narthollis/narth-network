use crate::common::WriteToBuffer;
use crate::protocols::arp::{ArpMessage, ArpState, ArpTable, Operation};
use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use crate::protocols::ipv4::icmp::DestinationUnreachableCode::{HostUnreachable, NetUnreachable};
use crate::protocols::ipv4::icmp::{
    DestinationUnreachableCode, DestinationUnreachableMessage,
    ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH, ICMPMessage, ICMPMessageTypes,
};
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header, prefix_to_mask};
use crate::runtime::address_table::AddressTable;
use crate::runtime::common::*;
use crate::runtime::route_table::{RouteInformation, RouteTable};
use mio::event::Event;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, RwLock, mpsc, oneshot};
use tracing::{debug, error, trace, trace_span};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to check address: {0}")]
    AddressCheckFailed(#[source] io::Error),
    #[error("Address removed before add completed")]
    AddressRemoved,
    #[error("Address in use")]
    AddressInUse,

    #[error("Route Unknown Source")]
    RouteUnknownSource(),
    #[error("Route Next Hop Unreachable")]
    RouteNextHopUnreachable(),

    #[error("Failed read {0} from shared state")]
    SharedDataReadFailed(&'static str),

    #[error("Control send failed")]
    ControlFailed,
}

impl From<mpsc::SendError<InterfaceControlMessage>> for Error {
    fn from(_value: mpsc::SendError<InterfaceControlMessage>) -> Self {
        Error::ControlFailed
    }
}

type Result<T> = std::result::Result<T, Error>;
type ResultSender<T> = oneshot::Sender<Result<T>>;

pub(crate) enum InterfaceControlMessage {
    IPv4AddressAdd(Ipv4Addr, u8, ResultSender<()>),
    IPv4AddressRemove(Ipv4Addr),
    IPv4RouteAdd {
        target: Ipv4Addr,
        target_mask: Ipv4Addr,
        next_hop: Ipv4Addr,
        src: Option<Ipv4Addr>,
        reply: ResultSender<()>,
    },
    IPv4RouteRemove(),
    Ping {
        target: Ipv4Addr,
        count: Option<usize>,
        interval: std::time::Duration,
        reply: ResultSender<super::ping::PingSession>,
    },
    Stop(),
}

pub struct Interface {
    control: mpsc::SyncSender<InterfaceControlMessage>,
    ipv4_addresses: Arc<RwLock<Vec<(Ipv4Addr, Ipv4Addr)>>>,
    ipv4_routes: Arc<RwLock<Vec<RouteInformation<Ipv4Addr>>>>,
}

impl Interface {
    pub(super) fn new(
        mtu: usize,
        mac_address: MacAddr,
        send: super::common::NetworkSender<NetworkSendPayload>,
    ) -> (Self, InterfaceWorker) {
        let (control_tx, control_rx) = mpsc::sync_channel(10);

        let worker = InterfaceWorker::new(control_rx, send, mtu, mac_address);
        let interface = Interface {
            control: control_tx,
            ipv4_addresses: worker.ipv4_addresses.shared(),
            ipv4_routes: worker.ipv4_route_table.shared(),
        };

        (interface, worker)
    }

    pub fn stop(&self) -> Result<()> {
        self.control
            .send(InterfaceControlMessage::Stop())
            .map_err(|_| Error::ControlFailed)
    }

    pub fn ping(
        &self,
        target: Ipv4Addr,
        count: Option<usize>,
        interval: Option<std::time::Duration>,
    ) -> Result<super::ping::PingSession> {
        let (tx, rx) = oneshot::channel();

        self.control
            .send(InterfaceControlMessage::Ping {
                target,
                count,
                interval: interval.unwrap_or_else(|| std::time::Duration::from_secs(1)),
                reply: tx,
            })
            .map_err(|_| Error::ControlFailed)?;

        rx.recv().map_err(|_| Error::ControlFailed)?
    }

    pub fn ipv4_address_add(&self, addr: Ipv4Addr, prefix: u8) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.control
            .send(InterfaceControlMessage::IPv4AddressAdd(addr, prefix, tx))?;

        rx.recv().unwrap_or_else(|e| {
            eprintln!("{}", e);
            Err(Error::ControlFailed)
        })
    }
    pub fn ipv4_address_remove(&self, addr: Ipv4Addr) -> Result<()> {
        self.control
            .send(InterfaceControlMessage::IPv4AddressRemove(addr))?;

        Ok(())
    }

    pub fn ipv4_addresses(&self) -> Result<Vec<Ipv4Addr>> {
        Ok(self
            .ipv4_addresses
            .read()
            .map_err(|_| Error::SharedDataReadFailed("ipv4_addresses"))?
            .iter()
            .map(|(addr, _)| *addr)
            .collect())
    }

    pub fn ipv4_route_add(
        &self,
        target: Ipv4Addr,
        prefix: u8,
        next_hop: Ipv4Addr,
        src: Option<Ipv4Addr>,
    ) -> Result<()> {
        let target_mask = prefix_to_mask(prefix);
        let target = target & target_mask;

        let (tx, rx) = oneshot::channel();

        self.control.send(InterfaceControlMessage::IPv4RouteAdd {
            target,
            target_mask,
            next_hop,
            reply: tx,
            src,
        })?;

        rx.recv().unwrap_or_else(|e| {
            eprintln!("{}", e);
            Err(Error::ControlFailed)
        })
    }

    pub fn ipv4_routes(&self) -> Result<Vec<RouteInformation<Ipv4Addr>>> {
        Ok(self
            .ipv4_routes
            .read()
            .map_err(|_| Error::SharedDataReadFailed("ipv4_routes"))?
            .clone())
    }

    pub fn ipv6_addresses(&self) -> Result<Vec<Ipv6Addr>> {
        Ok(vec![])
    }
}

pub(crate) struct InterfaceWorker {
    control_rx: mpsc::Receiver<InterfaceControlMessage>,
    network_send: NetworkSender<NetworkSendPayload>,
    mtu: usize,
    mac_addr: MacAddr,

    ping_manager: super::ping::PingManager,

    arp_table: ArpTable,
    ipv4_addresses: AddressTable<Ipv4Addr>,
    ipv4_route_table: RouteTable<Ipv4Addr>,
    ipv4_pending_addresses: Vec<(Ipv4Addr, Ipv4Addr, ResultSender<()>)>,
    ipv4_send_buffer: HashMap<Ipv4Addr, VecDeque<(IPv4Header, bytes::Bytes)>>,
}

impl InterfaceWorker {
    pub(super) fn new(
        control_rx: mpsc::Receiver<InterfaceControlMessage>,
        network_send: NetworkSender<NetworkSendPayload>,
        mtu: usize,
        mac_addr: MacAddr,
    ) -> Self {
        InterfaceWorker {
            control_rx,
            network_send,
            mtu,
            mac_addr,

            ping_manager: super::ping::PingManager::default(),

            arp_table: ArpTable::default(),
            ipv4_addresses: AddressTable::default(),
            ipv4_route_table: RouteTable::default(),
            ipv4_pending_addresses: Vec::default(),
            ipv4_send_buffer: HashMap::default(),
        }
    }

    const WAKE_TOKEN: mio::Token = mio::Token(0);

    pub fn run(&mut self) {
        let mut poll = mio::Poll::new().expect("failed to create mio::Poll");

        let waker = std::sync::Arc::new(
            mio::Waker::new(poll.registry(), Self::WAKE_TOKEN)
                .expect("failed to create mio::Waker"),
        );
        let (network_tx, network_rx) = std::sync::mpsc::channel();

        let sender = NetworkSender::new(waker, network_tx);
        self.network_send
            .send(NetworkSendPayload::Listen(self.mac_addr, sender))
            .expect("failed to send listen commadn to network");

        let mut events = mio::Events::with_capacity(1024);

        let mut running = true;
        while running {
            // TODO this delay really needs to be computed from the pending timers - right now its almost pointless to be using poll
            poll.poll(&mut events, None) //Some(std::time::Duration::from_micros(10)))
                .expect("interface poll failed");

            for event in events.iter() {
                running = self.on_poll_event(event, &network_rx);
            }
        }
    }

    fn on_poll_event(&mut self, _event: &Event, network_rx: &Receiver<NetworkRecvPayload>) -> bool {
        loop {
            if !self.perform_control() {
                return false;
            }
            match network_rx.try_recv() {
                Ok(NetworkRecvPayload::Packet(bytes)) => self.recv(bytes),
                Err(mpsc::TryRecvError::Empty) => {
                    break;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    println!("Interface {} disconnected", self.mac_addr);
                    return false;
                }
            }
            self.perform_timers();
        }
        true
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
                    .arp_table
                    .request(self.ipv4_pending_addresses[i].0, Ipv4Addr::UNSPECIFIED)
                {
                    ArpState::PendingWait => {}
                    ArpState::PendingRetry { .. }
                    | ArpState::ResolvedStale(_)
                    | ArpState::Restart => {
                        self.send_arp_request(
                            self.ipv4_pending_addresses[i].0,
                            Ipv4Addr::UNSPECIFIED,
                        );
                    }
                    ArpState::Timeout => {
                        let (addr, mask, reply) = self.ipv4_pending_addresses.remove(i);
                        self.ipv4_addresses.insert(addr, mask);
                        self.ipv4_route_table
                            .insert_or_update(addr & mask, mask, addr, None);
                        _ = reply.send(Ok(()));
                        self.send_gratuitous_arp(addr);
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
        self.send_arp_request(addr, Ipv4Addr::UNSPECIFIED);

        self.ipv4_pending_addresses
            .push((addr, prefix_to_mask(prefix), reply));
    }

    fn handle_ipv4_address_remove(&mut self, addr: Ipv4Addr) {
        // iterate in reverse order so we don't end up with shifting index shenanigans
        for i in (0..self.ipv4_pending_addresses.len()).rev() {
            if self.ipv4_pending_addresses[i].0 == addr {
                let (_, _, reply) = self.ipv4_pending_addresses.remove(i);
                reply.send(Err(Error::AddressRemoved)).unwrap();
            }
        }

        self.ipv4_route_table.remove_matching(|x| x.source == addr);
        self.ipv4_addresses.remove(&addr);
    }

    fn handle_ipv4_route_add(
        &mut self,
        target: Ipv4Addr,
        target_mask: Ipv4Addr,
        next_hop: Ipv4Addr,
        src: Option<Ipv4Addr>,
    ) -> Result<()> {
        let src = src
            .or_else(|| self.ipv4_addresses.first_with_subnet_containing(&next_hop))
            .ok_or(Error::RouteNextHopUnreachable())
            .and_then(|src| match self.ipv4_addresses.contains(&src) {
                true => Ok(src),
                false => Err(Error::RouteUnknownSource()),
            })?;

        self.ipv4_route_table
            .insert_or_update(target, target_mask, src, Some(next_hop));

        Ok(())
    }

    fn perform_timers(&mut self) {
        self.perform_arp_timers();
        for (target, message) in self.ping_manager.perform_timers() {
            trace!("ping managed asked us to send to {}: {:?}", target, message);
            self.send_ipv4(
                target,
                Ipv4Addr::UNSPECIFIED,
                IPProtocolTypes::ICMP,
                message,
            );
        }
    }

    fn perform_arp_timers(&mut self) {
        for (ip, source) in self.arp_table.pending() {
            match self.arp_table.request(ip, source) {
                ArpState::PendingWait => {} // Continue to wait
                ArpState::PendingRetry { source } => {
                    self.send_arp_request(ip, source);
                }
                // Look, I don't quite know how we would hit ResolvedStale here, but...
                ArpState::Resolved(mac) | ArpState::ResolvedStale(mac) => {
                    if let Some(mut queue) = self.ipv4_send_buffer.remove(&ip) {
                        for pending in queue.drain(..) {
                            self.send_ethernet(mac, EtherType::IPv4, pending);
                        }
                    }
                    // TODO Whatever else is needed now the address has been resovled - not sure what that is
                }
                // Restart is when the Timeout has gone stale or the Resolved has gone through stale out the other side
                ArpState::Timeout | ArpState::Restart => {
                    if let Some(mut queue) = self.ipv4_send_buffer.remove(&ip) {
                        for (ipv4header, payload) in queue.drain(..) {
                            self.recv_ipv4_icmp_unreachable(&DestinationUnreachableMessage {
                                code: DestinationUnreachableCode::HostUnreachable,
                                ipv4header,
                                datagram: payload.slice(..ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH),
                            });
                        }
                    }
                }
            }
        }
    }

    fn send(&self, packet: impl WriteToBuffer) {
        assert!(packet.encoded_length() <= self.mtu);

        let mut buffer = bytes::BytesMut::with_capacity(self.mtu);
        packet.write_to_buffer(&mut buffer);
        buffer.truncate(buffer.len());

        let buffer = buffer.freeze();

        if tracing::enabled!(tracing::Level::TRACE) {
            parse_and_log(&buffer);
        }

        _ = self
            .network_send
            .send(NetworkSendPayload::Packet(buffer))
            .map_err(io::Error::other);
    }

    fn send_ethernet(
        &self,
        destination: MacAddr,
        ether_type: EtherType,
        payload: impl WriteToBuffer,
    ) {
        let header = EthernetHeader::new(ether_type, self.mac_addr, destination);

        // Ethernet frames are caped at MTU
        assert!(header.encoded_length() + payload.encoded_length() <= self.mtu);

        self.send((header, payload))
    }

    fn send_ipv4(
        &mut self,
        destination: Ipv4Addr,
        source: Ipv4Addr,
        protocol: IPProtocolTypes,
        payload: impl WriteToBuffer,
    ) {
        // This is where we should do fragmentation if were supported it
        // instead I'm going panic (ethernet = (18 vlan assumption) ip = 20)
        assert!(payload.encoded_length() <= self.mtu - 18 - 20);
        // We shold probably drop + log in the following circumstace (or this is an actual case for sync result maybe
        // ICMP requires the first 64 bits/8 bytes of the paylaod be included in control mesages - so an IP frame
        // less than that is currenlty out of scope
        assert!(payload.encoded_length() > 8);

        let payload = {
            let mut buff = bytes::BytesMut::with_capacity(payload.encoded_length());
            payload.write_to_buffer(&mut buff);
            buff.freeze()
        };

        let raw_header = IPv4Header::new(protocol, source, destination, payload.len() as u16);

        let route = match self.ipv4_route_table.lookup(destination) {
            Some(route) => route,
            None => {
                self.recv_ipv4_icmp_unreachable(&DestinationUnreachableMessage {
                    code: NetUnreachable,
                    ipv4header: raw_header,
                    datagram: payload.slice(..ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH),
                });
                return;
            }
        };
        let source = source.or_unspecified(route.source);

        let header = IPv4Header::new(protocol, source, destination, payload.len() as u16);

        let next_hop = route.next_hop.unwrap_or(destination);

        let arp_state = self.arp_table.request(next_hop, source);
        trace!("arp table said {:?} for {}", arp_state, next_hop);

        // Check if we need to send an ARP request
        match arp_state {
            ArpState::PendingRetry { source } => self.send_arp_request(next_hop, source),
            ArpState::ResolvedStale(_) | ArpState::Restart => {
                self.send_arp_request(next_hop, source)
            }
            _ => {}
        }

        match arp_state {
            ArpState::PendingRetry { .. } | ArpState::PendingWait | ArpState::Restart => {
                trace!("so we buffer the message");
                self.ipv4_send_buffer
                    .entry(next_hop)
                    .or_default()
                    .push_back((header, payload));
            }
            ArpState::Resolved(dest_mac) | ArpState::ResolvedStale(dest_mac) => {
                trace!("so we send the message");
                self.send_ethernet(dest_mac, EtherType::IPv4, (header, payload));
            }
            ArpState::Timeout => {
                trace!("so we notify unreachable");
                self.recv_ipv4_icmp_unreachable(&DestinationUnreachableMessage {
                    code: HostUnreachable,
                    ipv4header: raw_header,
                    datagram: payload.slice(..ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH),
                });
            }
        };
    }

    fn recv(&mut self, frame: bytes::Bytes) {
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
            EtherType::IPv4 => self.recv_ipv4(ethernet_header, ethernet_payload),
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
            .arp_table
            .update_only(arp.source_mac(), arp.source_addr());

        if self.ipv4_addresses.contains(&arp.target_addr()) {
            if !merged {
                self.arp_table
                    .update_or_insert(arp.source_mac(), arp.source_addr());
                merged = true;
            }

            if arp.operation() == Operation::Request {
                let reply = arp.reply(self.mac_addr, arp.target_addr());
                self.send_ethernet(reply.target_mac(), EtherType::ARP, reply);
            }
        }

        if merged && let Some(mut queue) = self.ipv4_send_buffer.remove(&arp.source_addr()) {
            trace!(
                "resolved {} draining {} pending messages",
                arp.source_addr(),
                queue.len()
            );

            for pending in queue.drain(..) {
                self.send_ethernet(arp.source_mac(), EtherType::IPv4, pending);
            }
        }
    }

    fn recv_ipv4(&mut self, ethernet: EthernetHeader, bytes: bytes::Bytes) {
        let ip = match IPv4Header::from_bytes(&bytes) {
            Ok(ip) => ip,
            Err(e) => {
                debug!("failed to parse ipv4 header: {}", e);
                return;
            }
        };

        let payload = &bytes.slice(ip.encoded_length()..);

        trace_span!(
            "recv ipv4",
            ipv4_source = ip.source_address().to_string(),
            ipv4_destination = ip.destination_address().to_string()
        );
        trace!("Incoming IPv4 header: {:?}", ip);

        let merged = self
            .arp_table
            .update_or_insert(ethernet.source_address(), ip.source_address());
        let source_address = ip.source_address();

        match ip.protocol() {
            IPProtocolTypes::ICMP => _ = self.recv_ipv4_icmp(ip, payload),
            IPProtocolTypes::UDP => {
                // todo udp
            }
            IPProtocolTypes::TCP => {
                // todo tcp
            }
            _ => {
                // protocol we don't care about so drop it
            }
        };

        if merged && let Some(mut queue) = self.ipv4_send_buffer.remove(&source_address) {
            for pending in queue.drain(..) {
                _ = self.send_ethernet(ethernet.source_address(), EtherType::IPv4, pending);
            }
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
                self.send_ipv4(
                    ipv4_header.source_address(),
                    ipv4_header.destination_address(),
                    IPProtocolTypes::ICMP,
                    echo_reply,
                );
            }
            ICMPMessageTypes::EchoReply(reply) => {
                self.ping_manager.on_echo_reply(ipv4_header, reply);
            }
            ICMPMessageTypes::DestinationUnreachable(m) => self.recv_ipv4_icmp_unreachable(m),
            _ => {
                // TODO we need to parse the identifying data out of the control message's data and then
                // forward it to the protocol manager
                eprintln!("CONTROL MESSAGE: {:?}", icmp);
            }
        }
    }

    fn recv_ipv4_icmp_unreachable(&mut self, unreachable: &DestinationUnreachableMessage) {
        match unreachable.ipv4header.protocol() {
            IPProtocolTypes::ICMP => {
                self.ping_manager.on_unreachable(unreachable);
            }
            _ => {
                println!(
                    "Interface {} - ICMP Unreachable={:?} for {} datagram: {:?}",
                    self.mac_addr,
                    unreachable.code,
                    unreachable.ipv4header.destination_address(),
                    unreachable.datagram
                );
            }
        }
    }

    fn send_gratuitous_arp(&self, ipv4addr: Ipv4Addr) {
        let arp = ArpMessage::gratuitous(self.mac_addr, ipv4addr);
        self.send_ethernet(arp.target_mac(), EtherType::ARP, arp);
    }

    fn send_arp_request(&mut self, target_ipv4: Ipv4Addr, source_ipv4: Ipv4Addr) {
        if self.arp_table.can_send_request(target_ipv4, source_ipv4) {
            let arp = ArpMessage::request(self.mac_addr, target_ipv4, source_ipv4);
            self.send_ethernet(arp.target_mac(), EtherType::ARP, arp);
        }
    }
}

impl Drop for InterfaceWorker {
    fn drop(&mut self) {
        self.network_send
            .send(NetworkSendPayload::Closed(self.mac_addr))
            .expect("send closed");
    }
}

impl std::fmt::Display for InterfaceWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InterfaceWorker({})", self.mac_addr)
    }
}

trait OrUnspecified {
    fn or_unspecified(self, other: Self) -> Self;
}
impl OrUnspecified for Ipv4Addr {
    fn or_unspecified(self, other: Self) -> Self {
        if self.is_unspecified() {
            return other;
        }
        self
    }
}

fn parse_and_log(rem: &bytes::Bytes) {
    // this next part should be behind some kind of debug
    let e = match EthernetHeader::from_bytes(rem) {
        Ok(e) => e,
        Err(e) => {
            error!("failed to parse outgoing ethernet header: {}", e);
            return;
        }
    };
    trace!("Outgoing ethernet header: {:?}", e);

    let rem = &rem.slice(e.len()..);

    match e.ether_type() {
        EtherType::ARP => {
            let a = match ArpMessage::from_bytes(rem) {
                Ok(a) => a,
                Err(e) => {
                    error!("failed to parse outgoing arp message: {}", e);
                    return;
                }
            };
            trace!("Outgoing arp message: {:?}", a);
        }
        EtherType::IPv4 => {
            let ip = match IPv4Header::from_bytes(rem) {
                Ok(ip) => ip,
                Err(e) => {
                    error!("failed to parse outgoing ipv4 header: {}", e);
                    return;
                }
            };
            trace!("Outgoing IPv4 header: {:?}", ip);
            let rem = &rem.slice(ip.len()..);
            match ip.protocol() {
                IPProtocolTypes::ICMP => {
                    let icmp = match ICMPMessage::from_bytes(rem) {
                        Ok(icmp) => icmp,
                        Err(e) => {
                            error!("failed to parse outgoing icmp message: {}", e);
                            return;
                        }
                    };
                    trace!("Outgoing ICMP message: {:?}", icmp);
                }
                IPProtocolTypes::UDP => {}
                _ => {}
            }
        }
        _ => {}
    }
}
