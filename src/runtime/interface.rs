use crate::common::WriteToBuffer;
use crate::protocols::arp::{ArpMessage, ArpTable, Operation};
use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use crate::protocols::ipv4::icmp::{ICMPMessage, ICMPMessageTypes};
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header};
use crate::runtime::common::{
    HashSetSharedRead, NetworkHandle, NetworkRecvPayload, NetworkSendPayload,
};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock, mpsc, oneshot};
use std::thread::sleep;

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
    AddIPv4Address(Ipv4Addr, ResultSender<()>),
    RemoveAddress(Ipv4Addr),
    Stop(),
}

pub struct Interface {
    control: mpsc::SyncSender<InterfaceControlMessage>,
    ipv4_addresses: Arc<RwLock<Vec<Ipv4Addr>>>,
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

    pub fn add_ipv4_address(&self, addr: Ipv4Addr) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.control
            .send(InterfaceControlMessage::AddIPv4Address(addr, tx))?;

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

    ipv4_addresses: HashSetSharedRead<Ipv4Addr>,
    pending_addresses: Vec<(Ipv4Addr, ResultSender<()>)>,
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
                    sleep(std::time::Duration::from_millis(10));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    println!("Interface {} disconnected", self.mac_addr);
                    running = false;
                }
            }
        }
    }

    fn perform_control(&mut self) -> bool {
        while let Ok(msg) = self.control_rx.try_recv() {
            match msg {
                InterfaceControlMessage::AddIPv4Address(addr, reply) => {
                    self.handle_add_ipv4_address(addr, reply);
                }
                InterfaceControlMessage::RemoveAddress(addr) => {
                    for i in 0..self.pending_addresses.len() {
                        if self.pending_addresses[i].0 == addr {
                            let (_, reply) = self.pending_addresses.remove(i);
                            reply.send(Err(Error::AddressRemoved)).unwrap();
                        }
                    }
                    self.ipv4_addresses.remove(&addr);
                }
                InterfaceControlMessage::Stop() => {
                    return false;
                }
            }
        }

        if !self.pending_addresses.is_empty() {
            use crate::protocols::arp::ArpState;

            for i in 0..self.pending_addresses.len() {
                match self.arp_table.request(self.pending_addresses[i].0) {
                    ArpState::PendingWait => {}
                    ArpState::PendingRetry => {
                        _ = self.send_arp_request(self.pending_addresses[i].0);
                    }
                    ArpState::Timeout => {
                        let (addr, reply) = self.pending_addresses.remove(i);
                        self.ipv4_addresses.insert(addr);
                        _ = reply.send(Ok(()));
                        _ = self.send_gratuitous_arp(addr);
                    }
                    ArpState::Resolved(_) => {
                        let (_, reply) = self.pending_addresses.remove(i);
                        _ = reply.send(Err(Error::AddressInUse));
                    }
                }
            }
        }

        true
    }

    fn handle_add_ipv4_address(&mut self, addr: Ipv4Addr, reply: ResultSender<()>) {
        let arp = ArpMessage::request(self.mac_addr, addr);
        let ethernet = arp.create_ethernet();
        if let Err(err) = self.send((ethernet, arp)) {
            _ = reply.send(Err(Error::AddressCheckFailed(err)));
            return;
        }

        self.pending_addresses.push((addr, reply));
    }

    fn send(&self, packet: impl WriteToBuffer) -> io::Result<usize> {
        let mut buffer = bytes::BytesMut::zeroed(self.mtu);
        let count = packet.write_to_buffer(&mut buffer)?;
        buffer.truncate(count);

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

        match arp.operation() {
            Operation::Request => {
                if self.ipv4_addresses.contains(&arp.target_addr()) {
                    let reply = arp.reply(self.mac_addr, arp.target_addr());
                    let ether =
                        EthernetHeader::new(EtherType::ARP, self.mac_addr, reply.target_mac());

                    self.send((ether, reply))?;
                }
            }
            Operation::Reply => {
                self.arp_table.update_from_arp(arp);
            }
            Operation::Unknown(_) => {}
        }

        Ok(())
    }

    fn recv_ipv4(&mut self, ethernet: &EthernetHeader, bytes: &bytes::Bytes) -> io::Result<()> {
        let ip = IPv4Header::from_bytes(bytes)?;
        let payload = &bytes.slice(ip.len()..);
        println!(">> {:?}", ip);

        self.arp_table
            .update(ethernet.source_address(), ip.source_address());

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
