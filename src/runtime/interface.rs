use crate::common::WriteToBuffer;
use crate::protocols::arp::{ArpMessage, ArpState, ArpTable, Operation};
use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use crate::protocols::ipv4::icmp::{
    DestinationUnreachableCode, DestinationUnreachableMessage,
    ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH, ICMPMessage, ICMPMessageTypes,
};
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header, prefix_to_mask};
use crate::runtime::address_table::AddressTable;
use crate::runtime::common::{NetworkHandle, NetworkRecvPayload, NetworkSendPayload};
use crate::runtime::route_table::{RouteInformation, RouteTable};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock, mpsc, oneshot};

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
        count: Option<u16>,
        interval: std::time::Duration,
    }, // ResultSender<PingResponse>),
    Stop(),
}

pub struct Interface {
    control: mpsc::SyncSender<InterfaceControlMessage>,
    ipv4_addresses: Arc<RwLock<Vec<(Ipv4Addr, Ipv4Addr)>>>,
    ipv4_routes: Arc<RwLock<Vec<RouteInformation<Ipv4Addr>>>>,
}

impl Interface {
    pub(crate) fn new(
        mtu: usize,
        mac_address: MacAddr,
        send: mpsc::Sender<NetworkSendPayload>,
        recv: mpsc::Receiver<NetworkRecvPayload>,
    ) -> (Self, InterfaceWorker) {
        let (control_tx, control_rx) = mpsc::sync_channel(10);

        let worker =
            InterfaceWorker::new(control_rx, NetworkHandle { send, recv }, mtu, mac_address);
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
        count: Option<u16>,
        interval: Option<std::time::Duration>,
    ) -> Result<()> {
        self.control
            .send(InterfaceControlMessage::Ping {
                target,
                count,
                interval: interval.unwrap_or_else(|| std::time::Duration::from_secs(1)),
            })
            .map_err(|_| Error::ControlFailed)
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
    network: NetworkHandle,
    mtu: usize,
    mac_addr: MacAddr,
    // ipv6addr: Ipv6Addr,
    arp_table: ArpTable,

    ipv4_addresses: AddressTable<Ipv4Addr>,
    ipv4_pending_addresses: Vec<(Ipv4Addr, Ipv4Addr, ResultSender<()>)>,
    ipv4_route_table: RouteTable<Ipv4Addr>,
    ipv4_send_buffer: HashMap<Ipv4Addr, VecDeque<(IPv4Header, bytes::Bytes)>>,
}

impl InterfaceWorker {
    pub(crate) fn new(
        control_rx: mpsc::Receiver<InterfaceControlMessage>,
        network: NetworkHandle,
        mtu: usize,
        mac_addr: MacAddr,
    ) -> Self {
        InterfaceWorker {
            control_rx,
            network,
            mtu,
            mac_addr,
            arp_table: ArpTable::new(),

            ipv4_addresses: Default::default(),
            ipv4_pending_addresses: Default::default(),
            ipv4_route_table: RouteTable::<Ipv4Addr>::new(),
            ipv4_send_buffer: Default::default(),
        }
    }

    pub fn run(&mut self) {
        let mut running = true;
        while running {
            // Process all control messages before moving on
            running = self.perform_control();

            match self.network.recv.try_recv() {
                Ok(message) => match message {
                    NetworkRecvPayload::Packet(eth, bytes) => {
                        if let Err(err) = self.recv(&eth, &bytes) {
                            println!(
                                "Interface {}: Failed to handle packet: {}",
                                self.mac_addr, err
                            );
                        }
                    }
                },
                Err(mpsc::TryRecvError::Empty) => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    println!("Interface {} disconnected", self.mac_addr);
                    running = false;
                }
            }

            self.perform_timers();
        }
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
                    count: _count,
                    interval: _interval,
                } => {
                    let echo_request = ICMPMessage::new_echo_request(None, 1);
                    if let Err(err) = self.send_ipv4(
                        target,
                        Ipv4Addr::UNSPECIFIED,
                        IPProtocolTypes::ICMP,
                        echo_request,
                    ) {
                        eprintln!(
                            "Interface {}: Failed to ping {}: {}",
                            self.mac_addr, target, err
                        );
                    };
                }
                InterfaceControlMessage::Stop() => {
                    return false;
                }
            }
        }

        if !self.ipv4_pending_addresses.is_empty() {
            use crate::protocols::arp::ArpState;

            for i in (0..self.ipv4_pending_addresses.len()).rev() {
                match self.arp_table.request(self.ipv4_pending_addresses[i].0) {
                    ArpState::PendingWait => {}
                    ArpState::PendingRetry | ArpState::ResolvedStale(_) => {
                        _ = self.send_arp_request(self.ipv4_pending_addresses[i].0);
                    }
                    ArpState::Timeout => {
                        let (addr, mask, reply) = self.ipv4_pending_addresses.remove(i);
                        self.ipv4_addresses.insert(addr, mask);
                        self.ipv4_route_table
                            .insert_or_update(addr & mask, mask, addr, None);
                        _ = reply.send(Ok(()));
                        _ = self.send_gratuitous_arp(addr);
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
        let arp = ArpMessage::request(self.mac_addr, addr);
        let ethernet = arp.create_ethernet();
        if let Err(err) = self.send((ethernet, arp)) {
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
    }

    fn perform_arp_timers(&mut self) {
        for ip in self.arp_table.pending() {
            match self.arp_table.request(ip) {
                ArpState::PendingWait => {} // Continue to wait
                ArpState::PendingRetry => {
                    _ = self.send_arp_request(ip);
                }
                // Look, I don't quite know how we would hit ResolvedStale here, but...
                ArpState::Resolved(mac) | ArpState::ResolvedStale(mac) => {
                    if let Some(mut queue) = self.ipv4_send_buffer.remove(&ip) {
                        for pending in queue.drain(..) {
                            _ = self.send_ethernet(mac, EtherType::IPv4, pending);
                        }
                    }
                    // TODO Whatever else is needed now the address has been resovled - not sure what that is
                }
                ArpState::Timeout => {
                    if let Some(mut queue) = self.ipv4_send_buffer.remove(&ip) {
                        for (ipv4header, payload) in queue.drain(..) {
                            _ = self.recv_ipv4_icmp_unreachable(&DestinationUnreachableMessage {
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

    fn send(&self, packet: impl WriteToBuffer) -> io::Result<usize> {
        assert!(packet.encoded_length() <= self.mtu);

        let mut buffer = bytes::BytesMut::with_capacity(self.mtu);
        packet.write_to_buffer(&mut buffer);
        buffer.truncate(buffer.len());

        let buffer = buffer.freeze();

        // this next part should be behind some kind of debug
        let rem = &buffer.clone();
        let e = EthernetHeader::from_bytes(rem)?;
        let rem = &rem.slice(e.len()..);

        print_outgoing(1, &e);
        match e.ether_type() {
            EtherType::ARP => {
                let a = ArpMessage::from_bytes(rem)?;
                print_outgoing(2, &a);
            }
            EtherType::IPv4 => {
                let ip = IPv4Header::from_bytes(rem)?;
                let rem = &rem.slice(ip.len()..);
                print_outgoing(2, &ip);
                match ip.protocol() {
                    IPProtocolTypes::ICMP => {
                        let icmp = ICMPMessage::from_bytes(rem)?;
                        print_outgoing(2, &icmp);
                    }
                    IPProtocolTypes::UDP => {}
                    _ => {}
                }
            }
            _ => {}
        }

        let (send, recv) = oneshot::channel();

        self.network
            .send
            .send(NetworkSendPayload::Packet(buffer.clone(), send))
            .map_err(io::Error::other)?;

        recv.recv().map_err(io::Error::other)?
    }

    fn send_ethernet(
        &self,
        destination: MacAddr,
        ether_type: EtherType,
        payload: impl WriteToBuffer,
    ) -> io::Result<usize> {
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
    ) -> io::Result<()> {
        let route = self
            .ipv4_route_table
            .lookup(destination)
            .ok_or(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "No route to host",
            ))?;

        // This is where we should do fragmentation if were supported it
        // instead I'm going panic (ethernet = (18 vlan assumption) ip = 20)
        assert!(payload.encoded_length() <= self.mtu - 18 - 20);

        let header = IPv4Header::new(
            protocol,
            source.or_unspecified(route.source),
            destination,
            payload.encoded_length() as u16,
        );

        let mut payload_bytes = bytes::BytesMut::with_capacity(payload.encoded_length());
        payload.write_to_buffer(&mut payload_bytes);

        let payload_bytes = payload_bytes.freeze();

        let next_hop = route.next_hop.unwrap_or(destination);

        let arp_state = self.arp_table.request(next_hop);
        // Check if we need to send an ARP request
        match arp_state {
            ArpState::PendingRetry | ArpState::ResolvedStale(_) => {
                _ = self.send_arp_request(next_hop);
            }
            _ => {}
        }

        match arp_state {
            ArpState::PendingRetry | ArpState::PendingWait => {
                self.ipv4_send_buffer
                    .entry(next_hop)
                    .or_default()
                    .push_back((header, payload_bytes));
            }
            ArpState::Resolved(dest_mac) | ArpState::ResolvedStale(dest_mac) => {
                self.send_ethernet(dest_mac, EtherType::IPv4, (header, payload_bytes))?;
            }
            ArpState::Timeout => {
                return Err(io::Error::new(
                    io::ErrorKind::HostUnreachable,
                    "arp timeout",
                ));
            }
        };

        Ok(())
    }

    fn recv(&mut self, ethernet: &EthernetHeader, bytes: &bytes::Bytes) -> io::Result<()> {
        print_incoming(1, ethernet);

        match ethernet.ether_type() {
            EtherType::ARP => self.recv_arp(bytes),
            EtherType::IPv4 => self.recv_ipv4(ethernet, bytes),
            EtherType::IPv6 => Ok(()),
            t => Err(io::Error::other(format!(
                "unsupported ethernet type: {:?}",
                t
            ))),
        }
    }

    fn recv_arp(&mut self, bytes: &bytes::Bytes) -> io::Result<()> {
        let arp = ArpMessage::from_bytes(bytes)?;
        print_incoming(2, &arp);

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
                self.send_ethernet(reply.target_mac(), EtherType::ARP, reply)?;
            }
        }

        if merged && let Some(mut queue) = self.ipv4_send_buffer.remove(&arp.source_addr()) {
            for pending in queue.drain(..) {
                self.send_ethernet(arp.source_mac(), EtherType::IPv4, pending)?;
            }
        }

        Ok(())
    }

    fn recv_ipv4(&mut self, ethernet: &EthernetHeader, bytes: &bytes::Bytes) -> io::Result<()> {
        let ip = IPv4Header::from_bytes(bytes)?;
        let payload = &bytes.slice(ip.len()..);
        print_incoming(2, &ip);

        self.arp_table
            .update_or_insert(ethernet.source_address(), ip.source_address());

        match ip.protocol() {
            IPProtocolTypes::ICMP => self.recv_ipv4_icmp(ip, payload),
            IPProtocolTypes::UDP => Ok(()),
            IPProtocolTypes::TCP => Ok(()),
            _ => Ok(()),
        }
    }

    fn recv_ipv4_icmp(
        &mut self,
        ipv4_header: IPv4Header,
        payload: &bytes::Bytes,
    ) -> io::Result<()> {
        let icmp = ICMPMessage::from_bytes(payload)?;

        match &icmp.message {
            ICMPMessageTypes::Echo(echo) => {
                print_incoming(3, &icmp);

                let echo_reply = ICMPMessage::echo_reply(echo);
                self.send_ipv4(
                    ipv4_header.source_address(),
                    ipv4_header.destination_address(),
                    IPProtocolTypes::ICMP,
                    echo_reply,
                )?;
            }
            ICMPMessageTypes::EchoReply(reply) => {
                // TODO this should be forwarded to the ping manager
            }
            ICMPMessageTypes::DestinationUnreachable(m) => self.recv_ipv4_icmp_unreachable(m)?,
            _ => {
                // TODO we need to parse the identifying data out of the control message's data and then
                // forward it to the protocol manager
                eprintln!("CONTROL MESSAGE: {:?}", icmp);
            }
        }

        Ok(())
    }

    fn recv_ipv4_icmp_unreachable(
        &mut self,
        unreachable: &DestinationUnreachableMessage,
    ) -> io::Result<()> {
        println!(
            "Interface {} - ICMP Unreachable={:?} for {} datagram: {:?}",
            self.mac_addr,
            unreachable.code,
            unreachable.ipv4header.destination_address(),
            unreachable.datagram
        );

        Ok(())
    }

    fn send_gratuitous_arp(&self, ipv4addr: Ipv4Addr) -> std::io::Result<()> {
        let arp = ArpMessage::gratuitous(self.mac_addr, ipv4addr);
        self.send_ethernet(arp.target_mac(), EtherType::ARP, arp)?;

        Ok(())
    }

    fn send_arp_request(&mut self, ipv4addr: Ipv4Addr) -> std::io::Result<()> {
        if self.arp_table.can_send_request(ipv4addr) {
            let arp = ArpMessage::request(self.mac_addr, ipv4addr);
            self.send_ethernet(arp.target_mac(), EtherType::ARP, arp)?;
        }

        Ok(())
    }
}

impl Drop for InterfaceWorker {
    fn drop(&mut self) {
        self.network
            .send
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

static DO_LOG_MESSAGES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
#[inline]
fn do_log() -> bool {
    *DO_LOG_MESSAGES.get_or_init(|| std::env::var("LOG_MESSAGES").is_ok())
}
fn print_outgoing(level: usize, item: &impl std::fmt::Debug) {
    if do_log() {
        println!("{} {:?}", '<'.to_string().repeat(level), item);
    }
}
fn print_incoming(level: usize, item: &impl std::fmt::Debug) {
    if do_log() {
        println!("{} {:?}", '>'.to_string().repeat(level), item);
    }
}
