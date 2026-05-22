mod arp;
mod ethernet;

use crate::arp::{ArpMessage, ArpTable};
use crate::ethernet::{EtherType, EthernetMessage};
use std::thread::sleep;
use std::time::Duration;
use tun_rs::SyncDevice;

const MTU: u16 = 1500;
const ETHER_HEADER: usize = 38;
const FRAME: usize = MTU as usize + ETHER_HEADER;

const MAC_OURS: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const IPV4_OURS: [u8; 4] = [192, 168, 20, 1];
const MAC_HOST: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x10];
const MAC_BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

fn main() {
    let iface = tun_rs::DeviceBuilder::new()
        .name("narth%d")
        .layer(tun_rs::Layer::L2)
        .mac_addr(MAC_HOST)
        .mtu(MTU)
        .ipv4("192.168.20.2", 24, None)
        //.ipv6()
        .packet_information(false)
        .build_sync()
        .expect("Failed to build network interface");

    println!("created tun device: {}", iface.name().unwrap());
    sleep(Duration::from_secs(30));

    let mut arp_table = ArpTable::new();
    send_garp(&iface).expect("Failed to send garp message");

    loop {
        let mut buffer = vec![0; FRAME];

        let recv_size = iface.recv(&mut buffer).unwrap();
        let ethernet = EthernetMessage::from_bytes(&buffer[..recv_size]);

        // Neive mac filtering...
        if !ethernet.destination_address.eq(&MAC_OURS)
            && !ethernet.destination_address.eq(&MAC_BROADCAST)
        {
            // It's not for us
            continue;
        }

        println!("> {:?}", ethernet);
        match ethernet.ether_type {
            EtherType::ARP => {
                let arp = ArpMessage::from_bytes(ethernet.payload).unwrap();
                println!("> {:?}", arp);

                let mut buffer = vec![0; FRAME];

                let count = arp_table
                    .handle(ethernet, arp, MAC_OURS, IPV4_OURS, &mut buffer[..])
                    .unwrap();

                let r = EthernetMessage::from_bytes(&buffer[..count]);
                let ra = ArpMessage::from_bytes(r.payload).unwrap();

                println!("< {:?}", r);
                println!("< {:?}", ra);

                if count > 0 {
                    iface
                        .send(&buffer[..count])
                        .expect("Failed to send ARP message");
                }
            }
            EtherType::IPv4 => {}
            EtherType::IPv6 => {}
            _ => {}
        }

        //println!("recv: {:?}", &buffer[..size]);
    }
}

fn send_garp(iface: &SyncDevice) -> Result<(), std::io::Error> {
    let garp = ArpMessage::gratuitous(MAC_OURS, IPV4_OURS);
    let garp_ether = garp.create_ethernet();

    let mut buffer = vec![0; FRAME];
    let mut count = 0;
    count += garp_ether.write(&mut buffer[count..])?;
    count += garp.write(&mut buffer[count..])?;

    let r = EthernetMessage::from_bytes(&buffer[..count]);
    let ra = ArpMessage::from_bytes(r.payload).unwrap();

    println!("< {:?}", r);
    println!("< {:?}", ra);

    iface.send(&buffer[..count])?;

    Ok(())
}
