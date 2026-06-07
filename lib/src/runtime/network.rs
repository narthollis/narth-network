use crate::protocols::ethernet::EthernetHeader;
use crate::protocols::ethernet::mac::{BROADCAST, MacAddr};
use crate::runtime::NetworkBridge;
use crate::runtime::buffer_pool::BufferPool;
use crate::runtime::common::{
    BRIDGE_WAKE_TOKEN, NETWORK_WAKE_TOKEN, NetworkRecvPayload, NetworkSendPayload, NetworkSender,
    RingBufConsumer,
};
use crate::runtime::interface::{Interface, InterfaceWorker};
use std::fmt::{Debug, Formatter};
use std::sync::atomic::Ordering;
use tracing::{error, info, info_span, trace, warn};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to read addresses from interfaces")]
    EnumerateAddressError,

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error("Interface Handle is not in the correct state for sending")]
    InterfaceHandleIncorrectSendState,
    #[error("Interface send failed due to channel capacity")]
    InterfaceSendFailed { payload: NetworkRecvPayload },

    #[error("No Space for New Interface")]
    NoInterfaceSpace,

    #[error("Supplied MAC Address is already in use")]
    MacAddressConflict,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
enum WorkerOrHandle {
    Worker(Box<InterfaceWorker>),
    Handle(std::thread::JoinHandle<()>),
    Empty,
}

impl WorkerOrHandle {
    pub fn start(&mut self) {
        if matches!(self, Self::Worker(_)) {
            let current = std::mem::replace(self, Self::Empty);
            if let Self::Worker(mut worker) = current {
                let handle = std::thread::Builder::new()
                    .name(worker.to_string())
                    .spawn(move || worker.run())
                    .expect("failed to spawn network worker thread");

                *self = Self::Handle(handle);
            }
        }
    }
}

struct InterfaceHandle {
    receiver: super::common::NetworkRecvSender,
    worker: WorkerOrHandle,
    // interface: Arc<Interface>,
}
impl Debug for InterfaceHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceHandle")
            .field("worker", &self.worker)
            .finish_non_exhaustive()
    }
}

impl InterfaceHandle {
    pub fn send(&mut self, payload: NetworkRecvPayload) -> Result<()> {
        use ringbuf::traits::Producer;
        match self.worker {
            WorkerOrHandle::Handle(ref h) => {
                if let Err(payload) = self.receiver.try_push(payload) {
                    Err(Error::InterfaceSendFailed { payload })
                } else {
                    // Wake up the receiving end
                    h.thread().unpark();
                    Ok(())
                }
            }
            WorkerOrHandle::Worker(_) | WorkerOrHandle::Empty => {
                Err(Error::InterfaceHandleIncorrectSendState)
            }
        }
    }
}

struct InterfaceSendReceivers {
    ready_bits: std::sync::Arc<[std::sync::atomic::AtomicU64; 4]>,
    senders: [Option<RingBufConsumer<NetworkSendPayload>>; 256],
}

impl InterfaceSendReceivers {
    fn insert(&mut self, sender: RingBufConsumer<NetworkSendPayload>) -> Result<u8> {
        if let Some(index) = self.senders.iter().position(Option::is_none) {
            self.senders[index] = Some(sender);

            #[allow(clippy::cast_possible_truncation)] // We know that max index value us u8
            Ok(index as u8)
        } else {
            Err(Error::NoInterfaceSpace)
        }
    }

    fn ready(&mut self) -> ReadySendReceivers<'_> {
        let ready_bits = [
            self.ready_bits[0].swap(0, Ordering::Acquire),
            self.ready_bits[1].swap(0, Ordering::Acquire),
            self.ready_bits[2].swap(0, Ordering::Acquire),
            self.ready_bits[3].swap(0, Ordering::Acquire),
        ];

        ReadySendReceivers {
            ready_bits,
            senders: &mut self.senders,
            current_chunk: 0,
            // current_bit_idx: 0,
        }
    }
}

struct ReadySendReceivers<'a> {
    senders: &'a mut [Option<RingBufConsumer<NetworkSendPayload>>],
    ready_bits: [u64; 4],

    current_chunk: usize,
}
impl ReadySendReceivers<'_> {
    const SENDERS_FULL_LENGTH: usize = const { u64::BITS as usize * 4 };
}

impl<'a> Iterator for ReadySendReceivers<'a> {
    type Item = &'a mut RingBufConsumer<NetworkSendPayload>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current_chunk >= self.ready_bits.len() {
                return None;
            }
            if self.ready_bits[self.current_chunk] == 0 {
                self.current_chunk += 1;
                continue;
            }

            // Count the number of trailing zeros to get the index of the next ready index
            // This lets us skip strait to that ready index
            let next_ready = self.ready_bits[self.current_chunk].trailing_zeros() as usize;

            // We just need to reset that bit to zero now we are handling it
            self.ready_bits[self.current_chunk] &= !(1 << next_ready);

            // Convert the local bit index into an absolute index for our Senders array
            let current = next_ready + (u64::BITS as usize * self.current_chunk);
            // Then remove the consumed count
            let current = current - (Self::SENDERS_FULL_LENGTH - self.senders.len());

            // Somehow we were informed that a non-existent sender is ready
            if self.senders[current].is_none() {
                continue;
            }

            // Grab a local copy of senders so we can split it up and get access to just the part containing the sender
            let local_copy = std::mem::take(&mut self.senders);

            // Split the slice down to be just the item we care about, and everything after that
            // We need to adjust out bit index by the number of items we ahve already consumed
            let (_, rest) = local_copy.split_at_mut(current);
            let (sender, rest) = rest.split_at_mut(1);

            // Return the remaining items to senders
            self.senders = rest;

            // Extract our sender from the single item &[_] created by the split_at_mut(1)
            if let Some(sender) = &mut sender[0] {
                return Some(sender);
            }
        }
    }
}

impl Default for InterfaceSendReceivers {
    fn default() -> Self {
        Self {
            ready_bits: std::sync::Arc::default(),
            senders: [const { None }; 256],
        }
    }
}

impl Debug for InterfaceSendReceivers {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let senders = self
            .senders
            .iter()
            .map(|x| {
                if x.is_some() {
                    Some(&"RingBufConsumer<NetworkSendPayload>")
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        f.debug_struct("InterfaceSendReceivers")
            .field("ready_bits", &self.ready_bits)
            .field("senders", &senders)
            .finish()
    }
}

// TODO separate Network into Network / NetworkWorker
#[derive(Debug)]
pub struct Network<T: NetworkBridge> {
    bridge: T,
    interfaces: std::collections::HashMap<MacAddr, InterfaceHandle>,

    poll: mio::Poll,

    senders: InterfaceSendReceivers,

    started: bool,
    waker: std::sync::Arc<mio::Waker>,
}

impl<T: NetworkBridge + std::os::fd::AsRawFd> Network<T> {
    const RECV_QUEUE_SIZE: usize = 4096;
    const SEND_QUEUE_SIZE: usize = 4096;

    /// Create a new Network attached to the passed in Bridge
    ///
    /// # Arguments
    ///
    /// * `bridge`: Bridge to the Physical Network
    ///
    /// returns: Network<T>
    ///
    /// # Panics
    ///
    /// Panics when mio can not construct a watcher for the provided bridge
    pub fn new(bridge: T) -> Self {
        info!("Creating network");

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

        Self {
            bridge,
            interfaces: std::collections::HashMap::default(),

            poll,
            senders: InterfaceSendReceivers::default(),
            waker,

            started: true, // TODO Consider if we drop this or can actually make it work (see control before start)
        }
    }

    fn mac_addresses(&self) -> Vec<MacAddr> {
        self.interfaces
            .keys()
            .copied()
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

    pub fn add_interface(&mut self, mac_addr: MacAddr) -> Result<std::sync::Arc<Interface>> {
        use ringbuf::traits::Split;

        if self.mac_addresses().contains(&mac_addr) {
            return Err(Error::MacAddressConflict);
        }

        let (recv_producer, recv_consumer) =
            ringbuf::HeapRb::<NetworkRecvPayload>::new(Self::RECV_QUEUE_SIZE).split();
        let (send_producer, send_consumer) =
            ringbuf::HeapRb::<NetworkSendPayload>::new(Self::SEND_QUEUE_SIZE).split();

        let id = self.senders.insert(send_consumer)?;

        let (interface, worker) = Interface::new(
            self.bridge.mtu(),
            mac_addr,
            NetworkSender::new(
                self.waker.clone(),
                send_producer,
                self.senders.ready_bits.clone(),
                id,
            ),
            recv_consumer,
        );
        let interface = std::sync::Arc::new(interface);

        let mut handle = InterfaceHandle {
            receiver: recv_producer,
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

    /// Run the Network
    ///
    /// # Panics
    /// This may panic if the OS Event Poll (mio) can not be constructed
    ///
    pub fn run(&mut self) {
        info!("Running network");

        let mut closed = false;
        let mut events = mio::Events::with_capacity(1024);
        let mut pool = BufferPool::new(self.bridge.mtu() + EthernetHeader::MAX_LENGTH, 64);

        while !closed {
            self.poll
                // wait for the OS to let us know something is read, or 100ms whichever happens first
                .poll(&mut events, None) //Some(std::time::Duration::from_millis(100)))
                .expect("poll failed");

            for event in &events {
                //trace!("event={:?}", event);
                match event.token() {
                    BRIDGE_WAKE_TOKEN => closed = self.read_bridge(&mut pool),
                    NETWORK_WAKE_TOKEN => self.read_send_receiver(),
                    other_tokens => warn!("unexpected tokens received: {other_tokens:?}"),
                }
            }
        }
    }

    fn read_bridge(&mut self, pool: &mut BufferPool) -> bool {
        // TODO Consider some kind of budget to prevent starving out the send side
        loop {
            let mut buffer = pool.pop().unwrap_or_else(|| {
                // TODO Limit expansion
                pool.expand(64);
                pool.pop().expect("buffer pool is exhausted after expand")
            });

            match self.bridge.recv(&mut buffer) {
                Ok(0) => {
                    eprintln!("Connection closed");
                    return true;
                }
                Ok(recv_count) => {
                    buffer.advance(recv_count);
                    let buffer = bytes::Bytes::from_owner(buffer);

                    let s = info_span!("received packet", somerandomid = fastrand::u64(..));
                    let _e = s.enter();

                    self.on_recv(&buffer);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(err) => {
                    println!("failed to receive packet: {err:?}");
                }
            }
        }
        false
    }

    fn read_send_receiver(&mut self) {
        use ringbuf::traits::Consumer;

        // TODO Consider some kind of budget to avoid starving out the recv side
        for sender in self.senders.ready() {
            loop {
                match sender.try_pop() {
                    Some(NetworkSendPayload::Packet(packet)) => {
                        if let Err(err) = self.bridge.send(&packet) {
                            eprintln!("failed to send packet: {err:?}");
                        }
                    }
                    Some(NetworkSendPayload::Closed(mac)) => {
                        _ = self.interfaces.remove(&mac);
                        // TODO: also cleanup sender
                    }
                    None => break,
                }
            }
        }
    }

    fn on_recv(&mut self, frame: &bytes::Bytes) {
        if frame.len() < EthernetHeader::MIN_LENGTH {
            return;
        }

        let destination = match frame[..6].try_into() {
            Ok(a) => MacAddr::from_octets(a),
            Err(_) => return,
        };

        // If we get a broadcast forward it onto all of our Interfaces
        if destination == BROADCAST {
            for (mac, sender) in &mut self.interfaces {
                if let Err(err) = sender.send(NetworkRecvPayload::Packet(frame.clone())) {
                    error!(
                        "failed to send packet to {interface}: {error}",
                        interface = mac,
                        error = err
                    );
                }
            }
            return;
        }

        // Otherwise try and find an interface for the MAC address
        if let Some(sender) = self.interfaces.get_mut(&destination) {
            trace!(
                "received for {destination} with length: {length}",
                destination = destination,
                length = frame.len()
            );

            if let Err(err) = sender.send(NetworkRecvPayload::Packet(frame.clone())) {
                error!(
                    "Failed to send received packet to {interface}: {error}",
                    interface = destination,
                    error = err
                );
            }
        }
    }
}
