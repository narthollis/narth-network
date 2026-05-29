use crate::protocols::ethernet::EthernetHeader;
use crate::protocols::ethernet::mac::{BROADCAST, MacAddr};
use crate::runtime::NetworkBridge;
use crate::runtime::common::{NetworkRecvPayload, NetworkSendPayload};
use crate::runtime::interface::{Interface, InterfaceWorker};
use std::sync::{Arc, mpsc};
use std::thread;
use std::thread::{JoinHandle, sleep};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to read addresses from interfaces")]
    EnumerateAddressError,

    #[error(transparent)]
    IoError(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

enum WorkerOrHandle {
    Worker(InterfaceWorker),
    Handle(JoinHandle<()>),
    Empty,
}
impl WorkerOrHandle {
    pub fn start(&mut self) {
        if matches!(self, Self::Worker(_)) {
            let current = std::mem::replace(self, WorkerOrHandle::Empty);
            if let WorkerOrHandle::Worker(mut worker) = current {
                let handle = thread::Builder::new()
                    .name(worker.to_string())
                    .spawn(move || worker.run())
                    .unwrap();

                *self = WorkerOrHandle::Handle(handle);
            }
        }
    }
}

struct InterfaceHandle {
    receiver: mpsc::Sender<NetworkRecvPayload>,
    worker: WorkerOrHandle,
    // interface: Arc<Interface>,
}

pub struct Network<T: NetworkBridge> {
    bridge: T,
    interfaces: std::collections::HashMap<MacAddr, InterfaceHandle>,

    send_receiver: mpsc::Receiver<NetworkSendPayload>,
    send_sender: mpsc::Sender<NetworkSendPayload>,

    started: bool,
}

impl<T: NetworkBridge> Network<T> {
    pub fn new(bridge: T) -> Self {
        let (send_sender, send_recv) = mpsc::channel();

        Network {
            interfaces: Default::default(),
            bridge,
            send_sender,
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

    pub fn add_interface(&mut self, mac_addr: MacAddr) -> std::io::Result<Arc<Interface>> {
        if self.mac_addresses().contains(&mac_addr) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Mac address in use by host",
            ));
        }

        let (recv_tx, recv_rx) = mpsc::channel();

        let (interface, worker) = Interface::new(
            self.bridge.mtu(),
            mac_addr,
            self.send_sender.clone(),
            recv_rx,
        );
        let interface = Arc::new(interface);

        let mut handle = InterfaceHandle {
            receiver: recv_tx,
            worker: WorkerOrHandle::Worker(worker),
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
        let mut closed = false;

        while !closed {
            let mut buffer = bytes::BytesMut::zeroed(self.bridge.mtu());

            let mut would_block = false;
            let mut recv_empty = false;

            match self.bridge.recv(&mut buffer) {
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
                    if let Err(err) = reply.send(self.bridge.send(&bytes)) {
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
                sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    fn on_recv(&self, frame: &bytes::Bytes) -> std::io::Result<()> {
        let ethernet = &EthernetHeader::from_bytes(frame)?;
        let remaining = &frame.slice(ethernet.len()..);

        let target = ethernet.destination_address();
        // If we get a broadcast forward it onto all of our Interfaces
        if target.eq(&BROADCAST) {
            for (mac, sender) in self.interfaces.iter() {
                if let Err(err) = sender.receiver.send(NetworkRecvPayload::Packet(
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
            if let Err(err) = sender.receiver.send(NetworkRecvPayload::Packet(
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
