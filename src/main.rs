use narth_net::protocols::ethernet::mac::MacAddr;
use narth_net::runtime::network::Network;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::Duration;
use tun_rs::SyncDevice;

const MTU: u16 = 1500;

const MAC_OURS: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
const MAC_HOST: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x10);
const IPV4_OURS: Ipv4Addr = Ipv4Addr::new(192, 168, 174, 108);
const IPV4_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 20, 2);
const IPV4_NETWORK_PREFIX: u8 = 24;

fn main() -> std::io::Result<()> {
    let tap = Tap(tun_rs::DeviceBuilder::new()
        .name("narth%d")
        .layer(tun_rs::Layer::L2)
        .mac_addr(MAC_HOST.octets())
        .mtu(MTU)
        //.ipv4(IPV4_HOST, IPV4_NETWORK_PREFIX, None)
        //.ipv6()
        .packet_information(false)
        .build_sync()?);
    tap.0.set_nonblocking(true)?;
    println!("created tun device: {}", tap.0.name()?);

    let mut network = Network::new(tap);

    let interface = network.add_interface(MAC_OURS)?;

    // TODO make it so i can add / remove interfaces after starting...
    let jh = thread::spawn(move || network.run());

    if std::env::args().any(|a| a == "--wait") {
        std::thread::sleep(Duration::from_secs(10));
    }

    let inst = std::time::Instant::now();

    println!(
        "{:?} Trying to add IPv4 other address ({})...",
        inst.elapsed(),
        IPV4_OURS
    );
    if let Ok(()) = interface.ipv4_address_add(IPV4_OURS, IPV4_NETWORK_PREFIX) {
        println!("{:?} Added ipv4 address {}", inst.elapsed(), IPV4_OURS);
    }

    match interface.ipv4_route_add(
        Ipv4Addr::UNSPECIFIED,
        0,
        Ipv4Addr::from_octets([192, 168, 174, 1]),
        None,
    ) {
        Ok(_) => println!("{:?} Added IPv4 route", inst.elapsed()),
        Err(e) => eprintln!("Failed to add ipv4 route: {}", e),
    }

    println!("IPv4 Addresses: {:?}", interface.ipv4_addresses());
    println!("IPv4 Routes: {:?}", interface.ipv4_routes());

    if let Err(err) = interface.ping(Ipv4Addr::from_octets([1, 1, 1, 1]), Some(4), None) {
        println!("{:?} Failed to ping: {}", inst.elapsed(), err);
    }

    jh.join().expect("Failed to join network thread");

    Ok(())
}

struct Tap(SyncDevice);
impl narth_net::runtime::NetworkBridge for Tap {
    type Error = std::io::Error;

    fn mtu(&self) -> usize {
        self.0.mtu().unwrap_or(MTU) as usize
    }

    fn mac_addr(&self) -> MacAddr {
        self.0.mac_address().map(|x| x.into()).unwrap_or(MAC_HOST)
    }

    fn ipv4_addresses(&self) -> std::io::Result<impl IntoIterator<Item = Ipv4Addr>> {
        Ok(self
            .0
            .addresses()?
            .into_iter()
            .filter_map(|x| match x {
                IpAddr::V4(a) => Some(a),
                _ => None,
            })
            .collect::<Vec<_>>())
    }

    fn ipv6_addresses(&self) -> std::io::Result<impl IntoIterator<Item = Ipv6Addr>> {
        Ok(self
            .0
            .addresses()?
            .into_iter()
            .filter_map(|x| match x {
                IpAddr::V6(a) => Some(a),
                _ => None,
            })
            .collect::<Vec<_>>())
    }

    fn send(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.send(data)
    }

    fn recv(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(buffer)
    }
}
