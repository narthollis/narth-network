use narth_net::poller::Poller;
use narth_net::protocols::ethernet::mac::MacAddr;
use narth_net::runtime::interface::Interface;
use narth_net::runtime::network::Network;
use std::io::{Write, stdout};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;
use tun_rs::SyncDevice;

mod seq;

const MTU: u16 = 1500;

const MAC_OURS: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x31);
const MAC_HOST: MacAddr = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x10);
const IPV4_OURS: Ipv4Addr = Ipv4Addr::new(192, 168, 174, 108);
const IPV4_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 20, 2);
const IPV4_NETWORK_PREFIX: u8 = 24;

//#[tokio::main]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let seq_endpoint = "http://127.0.0.1:5341/ingest/otlp";
    let tracer_provider = seq::init_telemetry(seq_endpoint)?;

    tracing::info!(
        "Application booted and telemetry routing to Seq at {}.",
        seq_endpoint
    );

    s_main()?;

    tracing::info!("Application logic completed safely.");

    tracer_provider.shutdown();

    Ok(())
}

//noinspection D
fn s_main() -> Result<(), Box<dyn std::error::Error>> {
    // tracing_subscriber::registry()
    //     .with(fmt::layer().pretty())
    //     .with(tracing_subscriber::EnvFilter::from_default_env())
    //     .init();
    let tap = Tap(tun_rs::DeviceBuilder::new()
        .name("narth%d")
        .layer(tun_rs::Layer::L2)
        .mac_addr(MAC_HOST.octets())
        .mtu(MTU)
        //.l3_ipv4(IPV4_HOST, IPV4_NETWORK_PREFIX, None)
        //.ipv6()
        .packet_information(false)
        .build_sync()?);
    tap.0.set_nonblocking(true)?;
    println!("created tun device: {}", tap.0.name()?);

    let mut network = Network::new(tap);

    let interface = network.add_interface(MAC_OURS)?;

    // TODO make it so i can add / remove interfaces after starting...
    let jh = std::thread::spawn(move || network.run());

    if std::env::args().any(|a| a == "--wait") {
        std::thread::sleep(Duration::from_secs(10));
    }

    print!("Trying to add IPv4 address ({})...", IPV4_OURS);
    _ = stdout().flush();
    match interface.ipv4_address_add(IPV4_OURS, IPV4_NETWORK_PREFIX) {
        Ok(_) => println!(" Added"),
        Err(e) => {
            eprintln!("Error: {}", e);
            return Err(std::io::Error::other(e).into());
        }
    }

    match interface.ipv4_route_add(
        Ipv4Addr::UNSPECIFIED,
        0,
        Ipv4Addr::from_octets([192, 168, 174, 1]),
        None,
    ) {
        Ok(_) => println!("Added default l3_ipv4 route"),
        Err(e) => eprintln!("Failed to add default l3_ipv4 route: {}", e),
    }

    println!();
    println!(
        "IPv4 Addresses: {:?}",
        interface
            .ipv4_addresses()?
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("IPv4 Routes:");
    for route in interface.ipv4_routes()? {
        match route.next_hop {
            Some(next_hop) => println!(
                "  {}/{} via {} from {}",
                route.target,
                route.mask.to_bits().leading_ones() as u8,
                next_hop,
                route.source
            ),
            None => println!(
                "  {}/{} from {}",
                route.target,
                route.mask.to_bits().leading_ones() as u8,
                route.source
            ),
        }
    }

    // println!();
    // println!("Pinging device on network");
    // ping(&interface, [192, 168, 174, 57].into(), 4);
    //
    // println!();
    // println!("Pinging host (other network card)");
    // ping(&interface, [192, 168, 174, 175].into(), 4);

    println!();
    println!("Pinging router");
    ping(&interface, [192, 168, 174, 1].into(), 1);

    // // Unreachable
    // println!();
    // println!("Pinging net unreachable");
    // ping(&interface, [192, 0, 2, 1].into(), 4);
    // println!();
    // println!("Pinging host unreachable");
    // ping(&interface, [198, 51, 100, 1].into(), 4);
    //
    // println!();
    // println!("Ping the internet!");
    // ping(&interface, [1, 1, 1, 1].into(), 4);

    let mut udp = interface.bind_udp("0.0.0.0:12345")?;
    udp.set_nonblocking(false)?;
    let mut poller = Poller::default();
    let token = poller.register(&mut udp)?;
    loop {
        let ready = poller.poll();
        for event in ready {
            if event.token == token {
                loop {
                    let mut buf = [0u8; 1500];
                    match udp.recv_from(&mut buf) {
                        Ok((count, addr)) => {
                            println!("Received {} bytes from {}", count, addr);
                            udp.send_to(&buf[..count], addr)?;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Err(e) => println!("UDP recv error: {}", e),
                    }
                }
            }
        }
    }

    // loop {
    //     let mut buff = vec![0u8; MTU as usize];
    //     match udp.recv_from(&mut buff) {
    //         Ok((s, addr)) => {
    //             println!("Received: {}", String::from_utf8_lossy(&buff[0..s]));
    //             udp.send_to(&buff[..s], addr)?;
    //         }
    //         Err(err) => {
    //             println!("UDP recv error: {}", err);
    //         }
    //     }
    // }

    jh.join().expect("Failed to join network thread");

    Ok(())
}

fn ping(interface: &Interface, addr: Ipv4Addr, count: usize) {
    match interface.ping(addr, count.into(), None) {
        Ok(mut ping) => {
            for result in ping.into_iter() {
                match result.status {
                    narth_net::runtime::PingResultStatus::Success(Some(duration)) => {
                        println!(
                            "Ping {} - {} - Success - Took {:.4} ms",
                            result.target,
                            result.sequence + 1,
                            duration.as_secs_f64() * 1_000.0,
                        );
                    }
                    narth_net::runtime::PingResultStatus::Success(None) => {
                        println!("Ping {} - {} - Success", result.target, result.sequence + 1,);
                    }
                    narth_net::runtime::PingResultStatus::Timeout => {
                        println!(
                            "Ping {} - {} - Error Timeout",
                            result.target,
                            result.sequence + 1,
                        );
                    }
                    narth_net::runtime::PingResultStatus::Unreachable(err) => {
                        println!(
                            "Ping {} - {} - Error {}",
                            result.target,
                            result.sequence + 1,
                            err
                        );
                    }
                }
            }

            if let Some(stats) = &ping.stats {
                println!(
                    "Ping finished - Min: {:.4}ms Max: {:.4}ms Mean: {:.4}ms P95: {:.4}ms P99: {:.4}ms",
                    stats.min() as f64 / 1_000_000.0,
                    stats.max() as f64 / 1_000_000.0,
                    stats.mean() / 1_000_000.0,
                    stats.value_at_percentile(95.0) as f64 / 1_000_000.0,
                    stats.value_at_percentile(99.0) as f64 / 1_000_000.0,
                );
            } else {
                println!("Ping finished")
            }
        }
        Err(e) => eprintln!("Failed to ping: {}", e),
    }
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

impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
