mod ethernet;
mod arp;

use tun_rs::Layer;
use crate::arp::Arp;
use crate::ethernet::{EtherType, Ethernet};

const MTU: u16 = 1500;
const ETHER_HEADER: usize = 38;
const FRAME: usize = MTU as usize + ETHER_HEADER;

const MAC_OURS: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const MAC_HOST: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x10];
const MAC_BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

fn main() {
    let iface = tun_rs::DeviceBuilder::new()
        .name("narth%d")
        .layer(Layer::L2)
        .mac_addr(MAC_HOST)
        .mtu(MTU)
        .ipv4("192.168.20.2", 24, None)
        //.ipv6()
        .packet_information(false)
        .build_sync().expect("Failed to build network interface");

    println!("created tun device: {}", iface.name().unwrap());

    // TODO we need an ARP table

    loop {
        let mut buffer = vec![0; FRAME];

        let recv_size = iface.recv(&mut buffer).unwrap();
        let ethernet = Ethernet::from_bytes(&buffer[..recv_size]);

        if !ethernet.destination_address.eq(&MAC_OURS) && !ethernet.destination_address.eq(&MAC_BROADCAST) {
            // It's not for us
            continue;
        }

        println!("{} + payload: {}", ethernet, recv_size - ethernet.len());
        match ethernet.ether_type {
            EtherType::ARP => {
                let arp = Arp::from_bytes(ethernet.payload);
                println!("{:?}", arp);

                let mut write_buffer = vec![0; FRAME];
                let esize = ethernet.reply(&MAC_OURS, &mut write_buffer).expect("Failed to write ethernet header");
                let asize = arp.reply(MAC_OURS, [192, 168, 20, 1], &mut write_buffer[esize..]).expect("Failed to write reply");

                println!("ethernet={:?} arp={:?}", esize, asize);

                let resp = Ethernet::from_bytes(&write_buffer[..asize+esize]);
                println!("RESPONSE\n{}", resp);

                let resp_payload = Arp::from_bytes(resp.payload);
                println!("payload: {:?}", resp_payload);

                iface.send(&write_buffer[..esize+asize]).expect("Failed to write message to network interface");

            },
            EtherType::IPv4 => {}
            EtherType::IPv6 => {}
            _ => {},
        }


        //println!("recv: {:?}", &buffer[..size]);
    }
}
