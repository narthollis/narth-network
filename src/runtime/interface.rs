use crate::common::WriteToBuffer;
use crate::protocols::arp::{ArpMessage, ArpState, ArpTable, Operation};
use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use crate::protocols::ipv4::icmp::{ICMPMessage, ICMPMessageTypes};
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header, prefix_to_mask};
use crate::runtime::address_table::AddressTable;
use crate::runtime::common::{NetworkHandle, NetworkRecvPayload, NetworkSendPayload};
use crate::runtime::route_table::RouteTable;
use std::collections::VecDeque;
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
    #[error("Failed read addresses from shared state")]
    AddressReadFailed,

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
    AddIPv4Address(Ipv4Addr, u8, ResultSender<()>),
    RemoveAddress(Ipv4Addr),
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

    pub fn add_ipv4_address(&self, addr: Ipv4Addr, prefix: u8) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.control
            .send(InterfaceControlMessage::AddIPv4Address(addr, prefix, tx))?;

        rx.recv().unwrap_or_else(|e| {
            eprintln!("{}", e);
            Err(Error::ControlFailed)
        })
    }
    pub fn remove_ipv4_address(&self, addr: Ipv4Addr) -> Result<()> {
        self.control
            .send(InterfaceControlMessage::RemoveAddress(addr))?;

        Ok(())
    }

    pub fn ipv4_addresses(&self) -> Result<Vec<Ipv4Addr>> {
        Ok(self
            .ipv4_addresses
            .read()
            .map_err(|_| Error::AddressReadFailed)?
            .iter()
            .map(|(addr, _)| *addr)
            .collect())
    }

    pub fn ipv6_addresses(&self) -> Result<Vec<Ipv6Addr>> {
        Ok(vec![])
    }
}

struct PendingIpv4Packet {
    next_hop: Ipv4Addr,
    header: IPv4Header,
    payload: bytes::Bytes,
}

pub(crate) struct InterfaceWorker {
    control_rx: mpsc::Receiver<InterfaceControlMessage>,
    network: NetworkHandle,
    mtu: usize,
    mac_addr: MacAddr,
    // ipv6addr: Ipv6Addr,
    arp_table: ArpTable,

    ipv4_addresses: AddressTable<Ipv4Addr>,
    pending_addresses: Vec<(Ipv4Addr, Ipv4Addr, ResultSender<()>)>,
    ipv4_route_table: RouteTable<Ipv4Addr>,

    ipv4_send_buffer: VecDeque<PendingIpv4Packet>,
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
            pending_addresses: Default::default(),
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

            // TODO We need to check for ARP timeout and then handle the HostUnreacahble for matching pending
        }
    }

    fn perform_control(&mut self) -> bool {
        while let Ok(msg) = self.control_rx.try_recv() {
            match msg {
                InterfaceControlMessage::AddIPv4Address(addr, prefix, reply) => {
                    self.handle_add_ipv4_address(addr, prefix, reply);
                }
                InterfaceControlMessage::RemoveAddress(addr) => {
                    self.handle_remove_ipv4_address(addr);
                }
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
                        eprintln!("Interface {}: Failed to ping: {}", self.mac_addr, err);
                    };
                }
                InterfaceControlMessage::Stop() => {
                    return false;
                }
            }
        }

        if !self.pending_addresses.is_empty() {
            use crate::protocols::arp::ArpState;

            for i in (0..self.pending_addresses.len()).rev() {
                match self.arp_table.request(self.pending_addresses[i].0) {
                    ArpState::PendingWait => {}
                    ArpState::PendingRetry => {
                        _ = self.send_arp_request(self.pending_addresses[i].0);
                    }
                    ArpState::Timeout => {
                        let (addr, mask, reply) = self.pending_addresses.remove(i);
                        self.ipv4_addresses.insert(addr, mask);
                        self.ipv4_route_table
                            .insert_or_update(addr & mask, mask, addr, None);
                        _ = reply.send(Ok(()));
                        _ = self.send_gratuitous_arp(addr);
                    }
                    ArpState::Resolved(_) => {
                        let (_, _, reply) = self.pending_addresses.remove(i);
                        _ = reply.send(Err(Error::AddressInUse));
                    }
                }
            }
        }

        true
    }

    fn handle_add_ipv4_address(&mut self, addr: Ipv4Addr, prefix: u8, reply: ResultSender<()>) {
        let arp = ArpMessage::request(self.mac_addr, addr);
        let ethernet = arp.create_ethernet();
        if let Err(err) = self.send((ethernet, arp)) {
            _ = reply.send(Err(Error::AddressCheckFailed(err)));
            return;
        }

        self.pending_addresses
            .push((addr, prefix_to_mask(prefix), reply));
    }

    fn handle_remove_ipv4_address(&mut self, addr: Ipv4Addr) {
        // iterate in reverse order so we don't end up with shifting index shenanigans
        for i in (0..self.pending_addresses.len()).rev() {
            if self.pending_addresses[i].0 == addr {
                let (_, _, reply) = self.pending_addresses.remove(i);
                reply.send(Err(Error::AddressRemoved)).unwrap();
            }
        }

        self.ipv4_route_table.remove_matching(|x| x.source == addr);
        self.ipv4_addresses.remove(&addr);
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

        println!("< {:?}", e);
        match e.ether_type() {
            EtherType::ARP => {
                let a = ArpMessage::from_bytes(rem)?;
                println!("<< {:?}", a);
            }
            EtherType::IPv4 => {
                let ip = IPv4Header::from_bytes(rem)?;
                let rem = &rem.slice(ip.len()..);
                println!("<< {:?}", ip);
                match ip.protocol() {
                    IPProtocolTypes::ICMP => {
                        let icmp = ICMPMessage::from_bytes(rem)?;
                        println!("<<< {:?}", icmp);
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

        let mut payload_bytes = bytes::BytesMut::with_capacity(payload.encoded_length());
        payload.write_to_buffer(&mut payload_bytes);
        let payload_bytes = payload_bytes.freeze();

        let header = IPv4Header::new(
            protocol,
            source.or_unspecified(route.source),
            destination,
            payload_bytes.len() as u16,
        );

        let next_hop = route.next_hop.unwrap_or(destination);

        match self.arp_table.request(next_hop) {
            ArpState::PendingRetry => {
                _ = self.send_arp_request(next_hop);
                self.ipv4_send_buffer.push_back(PendingIpv4Packet {
                    next_hop,
                    header,
                    payload: payload_bytes,
                });
            }
            ArpState::PendingWait => {
                self.ipv4_send_buffer.push_back(PendingIpv4Packet {
                    next_hop,
                    header,
                    payload: payload_bytes,
                });
            }
            ArpState::Resolved(r) => {
                let ethernet = EthernetHeader::new(EtherType::IPv4, self.mac_addr, r);
                self.send((ethernet, header, payload))?;
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
        // println!();
        // println!();
        println!("> {:?}", ethernet);

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
        println!(">> {:?}", arp);

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
                let ether = EthernetHeader::new(EtherType::ARP, self.mac_addr, reply.target_mac());

                self.send((ether, reply))?;
            }
        }

        if merged {
            // process through things that were waiting for a potential arp reply
            // namely the ipv4_send_buffer
            let mut i = 0;
            while i < self.ipv4_send_buffer.len() {
                if self.ipv4_send_buffer[i].next_hop == arp.source_addr() {
                    let pending = self.ipv4_send_buffer.remove(i).unwrap();
                    let ethernet =
                        EthernetHeader::new(EtherType::IPv4, self.mac_addr, arp.source_mac());
                    self.send((ethernet, pending.header, pending.payload))?;
                } else {
                    i += 1;
                }
            }
        }

        Ok(())
    }

    fn recv_ipv4(&mut self, ethernet: &EthernetHeader, bytes: &bytes::Bytes) -> io::Result<()> {
        let ip = IPv4Header::from_bytes(bytes)?;
        let payload = &bytes.slice(ip.len()..);
        println!(">> {:?}", ip);

        self.arp_table
            .update_or_insert(ethernet.source_address(), ip.source_address());

        match ip.protocol() {
            IPProtocolTypes::ICMP => {
                let icmp = ICMPMessage::from_bytes(payload)?;

                if let ICMPMessageTypes::Echo(echo) = &icmp.message {
                    println!(">>> {:?}", echo);

                    let echo_reply = ICMPMessage::echo_reply(echo);
                    let ip_reply = IPv4Header::new(
                        IPProtocolTypes::ICMP,
                        ip.destination_address(),
                        ip.source_address(),
                        echo_reply.len(),
                    );
                    let ether_reply = EthernetHeader::new(
                        EtherType::IPv4,
                        self.mac_addr,
                        ethernet.source_address(),
                    );

                    self.send((ether_reply, ip_reply, echo_reply))?;
                } else {
                    eprintln!("CONTROL MESSAGE: {:?}", icmp);
                }
            }
            IPProtocolTypes::UDP => {}
            IPProtocolTypes::TCP => {}
            _ => {}
        }

        Ok(())
    }

    fn send_gratuitous_arp(&self, ipv4addr: Ipv4Addr) -> std::io::Result<()> {
        let arp = ArpMessage::gratuitous(self.mac_addr, ipv4addr);
        let ethernet = EthernetHeader::new(EtherType::ARP, self.mac_addr, arp.target_mac());

        self.send((ethernet, arp))?;

        Ok(())
    }

    fn send_arp_request(&mut self, ipv4addr: Ipv4Addr) -> std::io::Result<()> {
        if self.arp_table.can_send_request(ipv4addr) {
            let arp = ArpMessage::request(self.mac_addr, ipv4addr);
            let ethernet = EthernetHeader::new(EtherType::ARP, self.mac_addr, arp.target_mac());

            self.send((ethernet, arp))?;
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
