use crate::protocols::ethernet;
use crate::protocols::ethernet::EthernetHeader;
use crate::protocols::ethernet::mac::{BROADCAST, MacAddr};
use crate::runtime::NetworkBridge;
use crate::runtime::common::*;
use crate::runtime::interface::{Interface, InterfaceWorker};
use tracing::{info, info_span, span, trace};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to read addresses from interfaces")]
    EnumerateAddressError,

    #[error(transparent)]
    IoError(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

enum WorkerOrHandle {
    Worker(Box<InterfaceWorker>),
    Handle(std::thread::JoinHandle<()>),
    Empty,
}
impl WorkerOrHandle {
    pub fn start(&mut self) {
        if matches!(self, Self::Worker(_)) {
            let current = std::mem::replace(self, WorkerOrHandle::Empty);
            if let WorkerOrHandle::Worker(mut worker) = current {
                let handle = std::thread::Builder::new()
                    .name(worker.to_string())
                    .spawn(move || worker.run())
                    .unwrap();

                *self = WorkerOrHandle::Handle(handle);
            }
        }
    }
}

struct InterfaceHandle {
    receiver: Option<NetworkSender<NetworkRecvPayload>>,
    worker: WorkerOrHandle,
    // interface: Arc<Interface>,
}

// TODO separate Network into Network / NetworkWorker
pub struct Network<T: NetworkBridge> {
    bridge: T,
    interfaces: std::collections::HashMap<MacAddr, InterfaceHandle>,

    poll: mio::Poll,

    send_sender: NetworkSender<NetworkSendPayload>,
    send_receiver: std::sync::mpsc::Receiver<NetworkSendPayload>,

    started: bool,
}

impl<T: NetworkBridge + std::os::fd::AsRawFd> Network<T> {
    pub fn new(bridge: T) -> Self {
        info!("Creating network");
        let (send_sender, send_recv) = std::sync::mpsc::channel();

        super::BOOT_TIME.get_or_init(std::time::Instant::now);

        let poll = mio::Poll::new().expect("Failed to create mio poll");
        poll.registry()
            .register(
                &mut mio::unix::SourceFd(&bridge.as_raw_fd()),
                BRIDGE_WAKE_TOKEN,
                mio::Interest::READABLE,
            )
            .expect("Failed to register bridge as mio socket");
        let waker = std::sync::Arc::new(
            mio::Waker::new(poll.registry(), NETWORK_WAKE_TOKEN)
                .expect("Failed to create mio waker"),
        );

        Network {
            bridge,
            interfaces: std::collections::HashMap::default(),

            poll,
            send_sender: NetworkSender::new(waker, send_sender),

            send_receiver: send_recv,

            started: true, // TODO Consider if we drop this or can actually make it work (see control before start)
        }
    }

    fn mac_addresses(&self) -> Vec<MacAddr> {
        self.interfaces
            .keys()
            .cloned()
            .chain([self.bridge.mac_addr()])
            .collect()
    }

    // fn ipv4_addresses(&self) -> Result<Vec<Ipv4Addr>> {
    //     Ok(self
    //         .interfaces
    //         .values()
    //         .map(|i| i.interface.ipv4_addresses())
    //         .collect::<std::result::Result<Vec<Vec<Ipv4Addr>>, crate::runtime::interface::Error>>()
    //         .map_err(|_| Error::EnumerateAddressError)?
    //         .into_iter()
    //         .flatten()
    //         .chain(
    //             self.bridge
    //                 .ipv4_addresses()
    //                 .map_err(|_| Error::EnumerateAddressError)?,
    //         )
    //         .collect())
    // }

    pub fn add_interface(
        &mut self,
        mac_addr: MacAddr,
    ) -> std::io::Result<std::sync::Arc<Interface>> {
        if self.mac_addresses().contains(&mac_addr) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Mac address in use by host",
            ));
        }

        let (interface, worker) =
            Interface::new(self.bridge.mtu(), mac_addr, self.send_sender.clone());
        let interface = std::sync::Arc::new(interface);

        let mut handle = InterfaceHandle {
            receiver: None,
            worker: WorkerOrHandle::Worker(worker.into()),
            //interface: interface.clone(),
        };

        if self.started {
            handle.worker.start();
        }

        self.interfaces.insert(mac_addr, handle);

        Ok(interface)
    }

    pub fn start(&mut self) {
        for interface in self.interfaces.values_mut() {
            interface.worker.start();
        }
    }

    pub fn join_interfaces(&mut self) {
        for (_, interface) in self.interfaces.drain() {
            if let WorkerOrHandle::Handle(handle) = interface.worker {
                _ = handle.join();
            }
        }
    }

    pub fn run(&mut self) {
        info!("Running network");

        let mut closed = false;

        let mut events = mio::Events::with_capacity(1024);
        while !closed {
            self.poll
                // wait for the OS to let us know something is read, or 100ms whichever happens first
                .poll(&mut events, None) //Some(std::time::Duration::from_millis(100)))
                .expect("poll failed");

            for event in events.iter() {
                //trace!("event={:?}", event);
                match event.token() {
                    BRIDGE_WAKE_TOKEN => closed = self.read_bridge(),
                    NETWORK_WAKE_TOKEN => self.read_send_receiver(),
                    other_tokens => println!("unexpected tokens received: {:?}", other_tokens),
                }
            }
        }
    }

    fn read_bridge(&mut self) -> bool {
        loop {
            let mut buffer = bytes::BytesMut::zeroed(self.bridge.mtu());
            match self.bridge.recv(&mut buffer) {
                Ok(0) => {
                    eprintln!("Connection closed");
                    return true;
                }
                Ok(recv_count) => {
                    let s = info_span!("received packet", somerandomid = fastrand::u64(..));
                    let e_ = s.enter();

                    buffer.truncate(recv_count);

                    self.on_recv(&buffer.freeze());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(err) => {
                    println!("failed to receive packet: {:?}", err);
                }
            }
        }
        false
    }

    fn read_send_receiver(&mut self) {
        loop {
            match self.send_receiver.try_recv() {
                Ok(NetworkSendPayload::Packet(bytes)) => {
                    if let Err(err) = self.bridge.send(&bytes) {
                        eprintln!("failed to send packet: {:?}", err);
                    }
                }
                Ok(NetworkSendPayload::Listen(mac_addr, sender)) => {
                    if let Some(interface) = self.interfaces.get_mut(&mac_addr) {
                        interface.receiver = Some(sender);
                    }
                }
                Ok(NetworkSendPayload::Closed(mac)) => {
                    _ = self.interfaces.remove(&mac);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {}
            };
        }
    }

    fn on_recv(&self, frame: &bytes::Bytes) {
        if frame.len() < EthernetHeader::MIN_LENGTH {
            return;
        }

        let destination = match frame[..6].try_into() {
            Ok(a) => MacAddr::from_octets(a),
            Err(_) => return,
        };

        // If we get a broadcast forward it onto all of our Interfaces
        if destination == BROADCAST {
            for (mac, sender) in self.interfaces.iter() {
                if let Some(sender) = sender.receiver.as_ref()
                    && let Err(err) = sender.send(NetworkRecvPayload::Packet(frame.clone()))
                {
                    println!(
                        "Failed to send received packet to interface {}: {}",
                        mac, err
                    );
                }
            }
            return;
        }

        // Otherwise try and find an interface for the MAC address
        if let Some(sender) = self.interfaces.get(&destination)
            && let Some(sender) = sender.receiver.as_ref()
        {
            trace!(
                "received for {destination} with length: {length}",
                destination = destination,
                length = frame.len()
            );

            if let Err(err) = sender.send(NetworkRecvPayload::Packet(frame.clone())) {
                println!(
                    "Failed to send received packet to interface {}: {}",
                    destination, err
                );
            }
        }
    }
}
