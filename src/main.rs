mod arp;
mod common;
mod ethernet;
mod icmp;
mod interface;
mod ipv4;
mod mac;

use crate::arp::{ArpMessage, ArpTable};
use crate::ethernet::{EtherType, EthernetMessage};
use crate::icmp::{ICMPMessage, ICMPMessageTypes};
use crate::interface::{Interface, Network};
use crate::ipv4::{IPProtocolTypes, IPv4Header};
use crate::mac::MacAddr;
use std::fmt::Formatter;
use std::net::Ipv4Addr;
use std::thread::sleep;
use std::time::Duration;
use tun_rs::SyncDevice;

const MTU: u16 = 1500;
const ETHER_HEADER: usize = 38;
const FRAME: usize = MTU as usize + ETHER_HEADER;

const MAC_OURS: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
const MAC_HOST: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x10);
const IPV4_OURS: Ipv4Addr = Ipv4Addr::new(192, 168, 20, 1);
const IPV4_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 20, 2);
const IPV4_NETWORK_PREFIX: u8 = 24;

fn main() -> std::io::Result<()> {
    let connection = tun_rs::DeviceBuilder::new()
        .name("narth%d")
        .layer(tun_rs::Layer::L2)
        .mac_addr(MAC_HOST.octets())
        .mtu(MTU)
        .ipv4(IPV4_HOST, IPV4_NETWORK_PREFIX, None)
        //.ipv6()
        .packet_information(false)
        .build_sync()?;

    let mut network = Network::new(&connection).expect("Failed to build network interface");

    println!("created tun device: {}", network.device_name().unwrap());

    if std::env::args().any(|a| a == "--wait") {
        sleep(Duration::from_secs(10));
    }

    network.add_interface(MAC_OURS, IPV4_OURS)?;

    network.execute()
}

// let mut arp_table = ArpTable::new();
// send_garp(&iface).expect("Failed to send garp message");

// let ping = ICMPMessage::new_echo_request(None, 1);
// let ip = IPv4Header::new(
//     IPProtocolTypes::ICMP,
//     IPV4_OURS,
//     IPV4_HOST,
//     ping.len("constructing ipv4"),
// );
// let e = EthernetMessage::new(EtherType::IPv4, MAC_OURS, MAC_HOST);

// let buf = &mut [0u8; 98];
// let mut count = e.write(&mut buf[..]).unwrap();
// count += ip.write(&mut buf[count..]).unwrap();
// count += ping.write(&mut buf[count..]).unwrap();

//     //println!("recv: {:?}", &buffer[..size]);
// }

#[derive(Debug)]
struct ReceiveError(String);
impl std::error::Error for ReceiveError {}
impl std::fmt::Display for ReceiveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ReceiveError").field(&self.0).finish()
    }
}

fn on_recv(iface: &SyncDevice, arp_table: &mut ArpTable, frame: &[u8]) -> Result<(), ReceiveError> {
    let ethernet = EthernetMessage::from_bytes(frame);

    // Neive mac filtering...
    if !ethernet.destination_address().eq(&MAC_OURS)
        && !ethernet.destination_address().is_broadcast()
    {
        // It's not for us
        return Ok(());
    }

    println!();
    println!();
    println!("> {:?}", ethernet);
    match ethernet.ether_type() {
        EtherType::ARP => {
            let arp = ArpMessage::from_bytes(ethernet.payload())
                .map_err(|e| ReceiveError(format!("Failed to parse ARP message: {}", e)))?;

            println!("> {:?}", arp);
            println!();

            let mut buffer = vec![0; FRAME];
            //
            // arp_table
            //     .handle(ethernet, arp, MAC_OURS, IPV4_OURS, &mut buffer[..])
            //     .and_then(|count| iface.send(&buffer[..count]))
            //     .map_err(|e| ReceiveError(format!("Failed to send ARP response {:?}", e)))?;
        }
        EtherType::IPv4 => {
            let ipv4 = IPv4Header::from_bytes(ethernet.payload())
                .map_err(|e| ReceiveError(format!("Failed to parse IPv4 header: {}", e)))?;
            println!("> {:?}", ipv4);
            // TODO Check dest address is us and send an ICMP Destination Not Reachable otherwise

            match ipv4.protocol() {
                IPProtocolTypes::ICMP => {
                    let icmp = ICMPMessage::from_bytes(ipv4.payload()).map_err(|e| {
                        ReceiveError(format!("Failed to parse ICMP message: {}", e))
                    })?;

                    if let ICMPMessageTypes::Echo(echo) = &icmp.message {
                        println!("> {:?}", icmp);

                        let echo_reply = ICMPMessage::echo_reply(echo);

                        let ipv4_reply = IPv4Header::new(
                            IPProtocolTypes::ICMP,
                            ipv4.destination_address(),
                            ipv4.source_address(),
                            icmp.len("in echo reply ipv4 construction"),
                        );
                        let ethernet_reply = ethernet.create_reply(MAC_OURS);

                        let mut buffer = vec![0; FRAME];
                        let mut count = 0;
                        count += ethernet_reply.write(&mut buffer[count..]).map_err(|e| {
                            ReceiveError(format!("Failed to write ethernet reply: {}", e))
                        })?;
                        count += ipv4_reply.write(&mut buffer[count..]).map_err(|e| {
                            ReceiveError(format!("Failed to write ipv4 reply: {}", e))
                        })?;
                        count += echo_reply.write(&mut buffer[count..]).map_err(|e| {
                            ReceiveError(format!("Failed to write echo reply: {}", e))
                        })?;

                        println!();
                        let er = EthernetMessage::from_bytes(&buffer[..count]);
                        println!("< {:?}", er);
                        let ir = IPv4Header::from_bytes(er.payload()).unwrap();
                        println!("< {:?}", ir);
                        let r = ICMPMessage::from_bytes(ir.payload()).unwrap();
                        println!("< {:?}", r);

                        iface.send(&buffer[..count]).map_err(|e| {
                            ReceiveError(format!("Failed to send ICMP Echo Reply message: {}", e))
                        })?;
                    } else {
                        eprintln!("RECEIVED ICMP {:?}", icmp);
                    }

                    Ok(())
                }
                _ => Ok(()),
            }?;
        }
        EtherType::IPv6 => {}
        _ => {}
    }

    Ok(())
}

fn send_garp(iface: &SyncDevice) -> Result<(), std::io::Error> {
    let garp = ArpMessage::gratuitous(MAC_OURS, IPV4_OURS);
    let garp_ether = garp.create_ethernet();

    let mut buffer = vec![0; FRAME];
    let mut count = 0;
    count += garp_ether.write(&mut buffer[count..])?;
    count += garp.write(&mut buffer[count..])?;

    let r = EthernetMessage::from_bytes(&buffer[..count]);
    let ra = ArpMessage::from_bytes(r.payload()).unwrap();

    println!("< {:?}", r);
    println!("< {:?}", ra);

    iface.send(&buffer[..count])?;

    Ok(())
}
