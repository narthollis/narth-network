use crate::arp::{ArpMessage, ArpTable};
use crate::ethernet::{EtherType, EthernetMessage};
use crate::icmp::{ICMPMessage, ICMPMessageTypes};
use crate::ipv4::{IPProtocolTypes, IPv4Header};
use crate::mac::{BROADCAST, MacAddr};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr};
use std::thread::sleep;
use std::time::Duration;
use tun_rs::SyncDevice;

pub struct Interface<'a> {
    connection: &'a SyncDevice,
    mac_addr: MacAddr,
    // These should maybe be collections?
    ipv4addr: Ipv4Addr,
    // ipv6addr: Ipv6Addr,
    arp_table: ArpTable,
}

impl<'a> Interface<'a> {
    fn new(connection: &'a SyncDevice, mac_addr: MacAddr, ipv4addr: Ipv4Addr) -> Self {
        Interface {
            connection,
            mac_addr,
            ipv4addr,
            arp_table: ArpTable::new(), // I think this may end up needing to be per-network...
        }
    }

    pub fn mac_addr(&self) -> MacAddr {
        self.mac_addr
    }

    pub fn ipv4addr(&self) -> Ipv4Addr {
        self.ipv4addr
    }

    pub fn send(&self, buffer: &[u8]) -> std::io::Result<usize> {
        // this next part should be behind some kind of debug
        let e = EthernetMessage::from_bytes(buffer);
        println!("< {:?}", e);
        match e.ether_type() {
            EtherType::ARP => {
                let a = ArpMessage::from_bytes(e.payload());
                println!("< {:?}", e);
            }
            EtherType::IPv4 => {
                let ip = IPv4Header::from_bytes(e.payload())?;
                println!("< {:?}", e);
                match ip.protocol() {
                    IPProtocolTypes::ICMP => {
                        let icmp = ICMPMessage::from_bytes(e.payload())?;
                        println!("< {:?}", icmp);
                    }
                    IPProtocolTypes::UDP => {}
                    _ => {}
                }
            }
            _ => {}
        }

        self.connection.send(buffer)
    }

    fn send_arp(&self, message: ArpMessage) -> std::io::Result<usize> {
        let ether = EthernetMessage::new(EtherType::ARP, self.mac_addr, message.destination_mac());

        let mut buffer = vec![0u8; ether.header_len() + message.len()];

        let mut count = 0;
        count += ether.write(&mut buffer[count..])?;
        count += message.write(&mut buffer[count..])?;

        self.send(&buffer[..count])
    }

    fn recv(&mut self, frame: EthernetMessage) -> std::io::Result<()> {
        println!("> {:?}", frame);

        match frame.ether_type() {
            EtherType::ARP => self.recv_arp(frame),
            EtherType::IPv4 => self.recv_ipv4(frame),
            EtherType::IPv6 => Ok(()),
            t => Err(std::io::Error::other(format!(
                "unsupported ethernet type: {:?}",
                t
            ))),
        }
    }

    fn recv_arp(&mut self, ethernet: EthernetMessage) -> std::io::Result<()> {
        let arp = ArpMessage::from_bytes(ethernet.payload())?;
        println!("> {:?}", arp);

        let reply = self.arp_table.handle(arp, self.mac_addr, self.ipv4addr)?;

        self.send_arp(reply)?;

        Ok(())
    }

    fn recv_ipv4(&mut self, ethernet: EthernetMessage) -> std::io::Result<()> {
        let ip = IPv4Header::from_bytes(ethernet.payload())?;
        println!("> {:?}", ip);

        match ip.protocol() {
            IPProtocolTypes::ICMP => {
                let icmp = ICMPMessage::from_bytes(ethernet.payload())?;

                if let ICMPMessageTypes::Echo(echo) = &icmp.message {
                    println!("> {:?}", ip);

                    todo!("finish wiring up icmp and ipv4 send")
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
}

impl<'a> Display for Interface<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Interface({})", self.mac_addr)
    }
}

pub struct Network<'a> {
    interfaces: HashMap<MacAddr, Interface<'a>>,
    connection: &'a SyncDevice,
}

impl<'a> Network<'a> {
    pub fn new(connection: &'a SyncDevice) -> std::io::Result<Self> {
        connection.set_nonblocking(true)?;

        Ok(Network {
            connection,
            interfaces: Default::default(),
        })
    }

    pub fn device_name(&self) -> std::io::Result<String> {
        self.connection.name()
    }

    pub fn add_interface(&mut self, mac_addr: MacAddr, ipv4addr: Ipv4Addr) -> std::io::Result<()> {
        if self.connection.mac_address()?.eq(&mac_addr.octets()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Mac address in use by host",
            ));
        }
        if self.connection.addresses()?.contains(&IpAddr::V4(ipv4addr)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "IPv4 address in use by host",
            ));
        }

        // if !self.ipv4net.contains(&ipv4addr) {
        //     return Err(std::io::Error::new(
        //         std::io::ErrorKind::InvalidInput,
        //         "Our addresses must be in the same range as the host address",
        //     ));
        // }

        self.interfaces.insert(
            mac_addr,
            Interface::new(self.connection, mac_addr, ipv4addr),
        );

        Ok(())
        //Ok(self.interfaces.get(&mac_addr).unwrap())
    }

    pub fn execute(&mut self) -> std::io::Result<()> {
        let frame_size = self.connection.mtu()? as usize;
        loop {
            let mut buffer = vec![0; frame_size];

            match self.connection.recv(&mut buffer) {
                Ok(recv_count) => {
                    if let Err(err) = self.on_recv(&buffer[..recv_count]) {
                        println!("failed to handle received packet: {}", err);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    sleep(Duration::from_millis(10)); // TODO some better waiting than just 10ms
                }
                Err(err) => {
                    println!("failed to receive packet: {:?}", err);
                }
            }
        }
    }

    fn on_recv(&mut self, frame: &[u8]) -> std::io::Result<()> {
        let ethernet = EthernetMessage::from_bytes(frame);

        // If we get a broadcast forward it onto all of our Interfaces
        if ethernet.destination_address().eq(&BROADCAST) {
            for interface in self.interfaces.values_mut() {
                if let Err(err) = interface.recv(ethernet) {
                    println!(
                        "Interface {} failed to handle received packet: {}",
                        interface, err
                    );
                }
            }
            return Ok(());
        }

        // Otherwise try and find an interface for the MAC address
        if let Some(interface) = self.interfaces.get_mut(&ethernet.destination_address()) {
            #[allow(clippy::collapsible_if)] // This reads clearer as nested if-statements
            if let Err(err) = interface.recv(ethernet) {
                println!(
                    "Interface {} failed to handle received packet: {}",
                    interface, err
                );
            }
        }

        // It's not for us, so drop it
        Ok(())
    }
}
