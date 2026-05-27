use crate::arp::{ArpMessage, ArpTable};
use crate::common::WriteToBuffer;
use crate::ethernet::{EtherType, EthernetHeader};
use crate::icmp::{ICMPMessage, ICMPMessageTypes};
use crate::ipv4::{IPProtocolTypes, IPv4Header};
use crate::mac::{BROADCAST, MacAddr};
use ipnet::Ipv4Net;
use std::io;
use std::net::Ipv4Addr;
use std::sync::{mpsc, oneshot};
use std::thread::sleep;
use std::time::Duration;

enum NetworkSendPayload {
    Packet(bytes::Bytes, oneshot::Sender<io::Result<usize>>),
    Closed(MacAddr),
}
enum NetworkRecvPayload {
    Packet(EthernetHeader, bytes::Bytes),
}

struct InterfaceHandle {
    send: mpsc::Sender<NetworkSendPayload>,
    recv: mpsc::Receiver<NetworkRecvPayload>,
}

pub struct Interface {
    handle: InterfaceHandle,
    mtu: usize,
    mac_addr: MacAddr,
    // These should maybe be collections?
    ipv4addr: Ipv4Addr,
    // ipv6addr: Ipv6Addr,
    arp_table: ArpTable,
}

impl Interface {
    fn new(handle: InterfaceHandle, mtu: usize, mac_addr: MacAddr, ipv4addr: Ipv4Addr) -> Self {
        Interface {
            mtu,
            handle,
            mac_addr,
            ipv4addr,
            arp_table: ArpTable::new(), // I think this may end up needing to be per-network...
        }
    }

    pub fn execute(&mut self) {
        if let Err(err) = self.send_garp() {
            eprintln!("Failed to send gratuitous ARP message: {}", err);
        }

        while let Ok(message) = self.handle.recv.recv() {
            match message {
                NetworkRecvPayload::Packet(eth, bytes) => {
                    if let Err(err) = self.recv(&eth, &bytes) {
                        println!(
                            "Interface {}: Failed to handle packet: {}",
                            self.mac_addr, err
                        );
                    }
                }
            }
        }
    }

    fn send(&self, packet: impl WriteToBuffer) -> std::io::Result<usize> {
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

        self.handle
            .send
            .send(NetworkSendPayload::Packet(buffer.clone(), send))
            .map_err(io::Error::other)?;

        recv.recv().map_err(io::Error::other)?
    }

    fn recv(&mut self, ethernet: &EthernetHeader, bytes: &bytes::Bytes) -> io::Result<()> {
        println!();
        println!();
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

        let reply = self.arp_table.handle(arp, self.mac_addr, self.ipv4addr)?;
        let ether = EthernetHeader::new(EtherType::ARP, self.mac_addr, reply.destination_mac());

        self.send((ether, reply))?;

        Ok(())
    }

    fn recv_ipv4(&mut self, ethernet: &EthernetHeader, bytes: &bytes::Bytes) -> io::Result<()> {
        let ip = IPv4Header::from_bytes(bytes)?;
        let payload = &bytes.slice(ip.len()..);
        println!(">> {:?}", ip);

        match ip.protocol() {
            IPProtocolTypes::ICMP => {
                let icmp = ICMPMessage::from_bytes(payload)?;

                if let ICMPMessageTypes::Echo(echo) = &icmp.message {
                    println!(">>> {:?}", echo);

                    let echo_reply = ICMPMessage::echo_reply(echo);
                    let ip_reply = IPv4Header::new(
                        IPProtocolTypes::ICMP,
                        self.ipv4addr,
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

    fn send_garp(&self) -> std::io::Result<()> {
        let arp = ArpMessage::gratuitous(self.mac_addr, self.ipv4addr);
        let ethernet = EthernetHeader::new(EtherType::ARP, self.mac_addr, arp.destination_mac());

        self.send((ethernet, arp))?;

        Ok(())
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.handle
            .send
            .send(NetworkSendPayload::Closed(self.mac_addr))
            .expect("send closed");
    }
}

impl std::fmt::Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Interface({})", self.mac_addr)
    }
}

pub struct Network {
    interfaces: std::collections::HashMap<MacAddr, mpsc::Sender<NetworkRecvPayload>>,
    mac_host: MacAddr,
    ipv4_host: Ipv4Net,

    mtu: usize,

    send_receiver: mpsc::Receiver<NetworkSendPayload>,
    send_sender: mpsc::Sender<NetworkSendPayload>,
}

impl Network {
    pub fn new(mac_host: MacAddr, ipv4_host: Ipv4Net, mtu: usize) -> std::io::Result<Self> {
        let (send_sender, send_recv) = mpsc::channel();

        Ok(Network {
            mac_host,
            ipv4_host,
            mtu,
            interfaces: Default::default(),
            send_sender,
            send_receiver: send_recv,
        })
    }

    // pub fn device_name(&self) -> std::io::Result<String> {
    //     self.connection.name()
    // }

    pub fn add_interface(
        &mut self,
        mac_addr: MacAddr,
        ipv4addr: Ipv4Addr,
    ) -> std::io::Result<Interface> {
        if self.mac_host.eq(&mac_addr) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Mac address in use by host",
            ));
        }
        if self.ipv4_host.addr().eq(&ipv4addr) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "IPv4 address in use by host",
            ));
        }

        if !self.ipv4_host.contains(&ipv4addr) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Our addresses must be in the same range as the host address",
            ));
        }

        let (recv_sender, recv_receiver) = mpsc::channel();

        let handle = InterfaceHandle {
            send: self.send_sender.clone(),
            recv: recv_receiver,
        };

        self.interfaces.insert(mac_addr, recv_sender);

        Ok(Interface::new(handle, self.mtu, mac_addr, ipv4addr))
    }

    pub fn execute(&mut self, wait: Option<Duration>) -> std::io::Result<()> {
        let connection = tun_rs::DeviceBuilder::new()
            .name("narth%d")
            .layer(tun_rs::Layer::L2)
            .mac_addr(self.mac_host.octets())
            .mtu(self.mtu as u16)
            .ipv4(self.ipv4_host.addr(), self.ipv4_host.prefix_len(), None)
            //.ipv6()
            .packet_information(false)
            .build_sync()?;

        println!("created tun device: {}", connection.name()?);
        connection
            .set_nonblocking(false)
            .expect("failed to set non-blocking");

        if let Some(wait) = wait {
            sleep(wait);
        }

        let mut closed = false;

        while !closed {
            let mut buffer = bytes::BytesMut::zeroed(self.mtu);

            let mut would_block = false;
            let mut recv_empty = false;

            match connection.recv(&mut buffer) {
                Ok(0) => {
                    eprintln!("Connection closed");
                    closed = true;
                }
                Ok(recv_count) => {
                    buffer.truncate(recv_count);

                    if let Err(err) = self.on_recv(&buffer.freeze()) {
                        println!("failed to handle received packet: {}", err);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    would_block = true;
                }
                Err(err) => {
                    println!("failed to receive packet: {:?}", err);
                }
            }
            match self.send_receiver.try_recv() {
                Ok(NetworkSendPayload::Packet(bytes, reply)) => {
                    if let Err(err) = reply.send(connection.send(&bytes)) {
                        println!("failed to send reply: {:?}", err);
                    }
                }
                Ok(NetworkSendPayload::Closed(mac)) => {
                    _ = self.interfaces.remove(&mac);
                }
                Err(mpsc::TryRecvError::Empty) => {
                    recv_empty = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => (),
            }
            if would_block && recv_empty {
                sleep(std::time::Duration::from_millis(100));
            }
        }

        Ok(())
    }

    fn on_recv(&self, frame: &bytes::Bytes) -> std::io::Result<()> {
        let ethernet = &EthernetHeader::from_bytes(frame)?;
        let remaining = &frame.slice(ethernet.len()..);

        let target = ethernet.destination_address();
        // If we get a broadcast forward it onto all of our Interfaces
        if target.eq(&BROADCAST) {
            for (mac, sender) in self.interfaces.iter() {
                if let Err(err) = sender.send(NetworkRecvPayload::Packet(
                    ethernet.clone(),
                    remaining.clone(),
                )) {
                    println!(
                        "Failed to send received packet to interface {}: {}",
                        mac, err
                    );
                }
            }
            return Ok(());
        }

        // Otherwise try and find an interface for the MAC address
        if let Some(sender) = self.interfaces.get(&ethernet.destination_address()) {
            #[allow(clippy::collapsible_if)] // This reads clearer as nested if-statements
            if let Err(err) = sender.send(NetworkRecvPayload::Packet(
                ethernet.clone(),
                remaining.clone(),
            )) {
                println!(
                    "Failed to send received packet to interface {}: {}",
                    ethernet.destination_address(),
                    err
                );
            }
        }

        // It's not for us, so drop it
        Ok(())
    }
}
