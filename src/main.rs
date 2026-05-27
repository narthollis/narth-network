#![feature(oneshot_channel)]

mod arp;
mod common;
mod ethernet;
mod icmp;
mod interface;
mod ipv4;
mod mac;

use crate::interface::Network;
use crate::mac::MacAddr;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use std::thread;
use std::thread::sleep;
use std::time::Duration;

const MTU: u16 = 1500;

const MAC_OURS: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
const MAC_HOST: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x10);
const IPV4_OURS: Ipv4Addr = Ipv4Addr::new(192, 168, 20, 1);
const IPV4_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 20, 2);
const IPV4_NETWORK_PREFIX: u8 = 24;

fn main() -> std::io::Result<()> {
    let mut network = Network::new(
        MAC_HOST,
        Ipv4Net::new(IPV4_HOST, IPV4_NETWORK_PREFIX).unwrap(),
        MTU as usize,
    )
    .expect("Failed to build network interface");

    let wait = match std::env::args().any(|a| a == "--wait") {
        true => Some(Duration::from_secs(10)),
        false => None,
    };

    let mut iface1 = network.add_interface(MAC_OURS, IPV4_OURS)?;

    let iface1_jh = thread::spawn(move || iface1.execute());

    network.execute(wait)?;

    let _ = iface1_jh.join();

    Ok(())
}
