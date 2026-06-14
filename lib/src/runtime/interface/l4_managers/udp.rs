use crate::poller::{PollerReadRegister, PollerWriteRegister, WakeHandle};
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header};
use crate::protocols::udp::UdpHeader;
use crate::ready_by_bits::IterReadyByBits;
use crate::runtime::buffer_pool::{BufferPool, WriteTrackingBuffer};
use crate::runtime::interface::l3_ipv4::IPv4Handler;
use crate::runtime::interface::{InterfaceContext, SendError, SendResult};
use crate::write_to_buffer::WriteToBuffer;
use ringbuf::consumer::Consumer;
use ringbuf::traits::{Observer, Producer, Split};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{trace, trace_span, warn};

#[derive(Debug)]
pub struct UdpManager {
    sockets: HashMap<SocketAddr, UdpSocketHandle>,
    ready_bits: Arc<[AtomicU64; 16]>,
    socket_ids: Box<[Option<SocketAddr>; u64::BITS as usize * 16]>,
}

impl Default for UdpManager {
    fn default() -> Self {
        Self {
            sockets: HashMap::default(),
            ready_bits: Arc::default(),
            socket_ids: vec![Option::<SocketAddr>::None; u64::BITS as usize * 16]
                .into_boxed_slice()
                .try_into()
                .expect("the initialisation size didn't match the declared size"),
        }
    }
}

impl UdpManager {
    pub fn bind(&mut self, ctx: &InterfaceContext, addr: SocketAddr) -> Result<UdpSocket> {
        if !addr.is_ipv4() {
            // For now reject any IPv6 stuff because we haven't implemented it
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ipv6 is not yet supported",
            ));
        }

        if self.sockets.contains_key(&addr) {
            return Err(Error::new(ErrorKind::AddrInUse, "address already in use"));
        }

        if addr.ip().is_unspecified() && self.sockets.keys().any(|x| x.port() == addr.port())
            || self
                .sockets
                .keys()
                .any(|x| x.ip().is_unspecified() && x.port() == addr.port())
        {
            return Err(Error::new(ErrorKind::AddrInUse, "address already in use"));
        }

        let (recv_tx, recv_rx) = ringbuf::HeapRb::<UdpRecvMessage>::new(1024).split();
        let (send_tx, send_rx) = ringbuf::HeapRb::<UdpSendMessage>::new(1024).split();

        let socket_id = self
            .socket_ids
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::OutOfMemory,
                    "no available socket slots (max 1024)",
                )
            })?;
        self.socket_ids[socket_id] = Some(addr);

        let payload_max_size = ctx.mtu
            - if addr.is_ipv4() {
                IPv4Header::LENGTH_NO_OPTIONS
            } else {
                todo!("IPv6Header::LENGTH_NO_OPTIONS")
            }
            - UdpHeader::LENGTH;

        let shared_state = Arc::new(UdpSocketSharedState {
            send_result: SharableUdpSendResult::default(),

            connected_to: RwLock::default(),

            allow_broadcast: AtomicBool::new(false),
            is_nonblocking: AtomicBool::new(false),
            max_payload_size: AtomicUsize::new(payload_max_size),
        });

        let handle = UdpSocketHandle {
            recv_tx,
            send_rx,
            peer_addr: None,
            shared_state: shared_state.clone(),
            local_addr: addr,
            read_wake_handle: None,
            write_wake_handle: None,
        };

        let socket = UdpSocket {
            context: UdpSocketContext {
                recv_rx,
                send_tx,
                buffer_pool: BufferPool::new(payload_max_size, 64),
                thread_handle: std::thread::current(),
                ready_bits: self.ready_bits.clone(),
                socket_id,
            },
            socket_addr: addr,
            shared_state,
        };

        self.sockets.insert(addr, handle);

        println!("bound {:?}", addr);

        Ok(socket)
    }

    pub fn recv(&mut self, source_addr: IpAddr, destination_addr: IpAddr, bytes: &bytes::Bytes) {
        trace!(
            "Incoming UDP from {:?} to {:?}",
            source_addr, destination_addr
        );

        let Ok(udp_header) = UdpHeader::from_bytes(bytes) else {
            warn!("UDP Parse failed");
            return;
        };

        trace_span!("udp recv", source_addr=?source_addr, source_port=?udp_header.source_port(), destination_addr=?destination_addr, destination_port=?udp_header.destination_port());

        let payload = bytes.slice(udp_header.encoded_length()..udp_header.datagram_length());

        match (source_addr, destination_addr) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                if !udp_header.validate_checksum_v4(&source, &destination, &payload) {
                    warn!("UDP Checksum failed");
                    return;
                }
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                todo!("validate udp6 {source:?} {destination:?}")
            }
            _ => return, // Miss-matched address kinds
        }

        //dbg!("udp", source_addr, destination_addr);

        let socket = {
            // First try and find the socket by actual IP
            if let Some(socket) = self.sockets.get_mut(&SocketAddr::new(
                destination_addr,
                udp_header.destination_port(),
            )) {
                socket
            } else if let Some(socket) = self.sockets.get_mut(&SocketAddr::new(
                destination_addr.to_unspecified(),
                udp_header.destination_port(),
            )) {
                socket
            } else {
                return;
            }
        };

        trace!("found listener {socket:?}");

        let source = SocketAddr::new(source_addr, udp_header.source_port());
        if let Some(peer) = socket.peer_addr
            && source != peer
        {
            trace!("socket has configured peer ({peer:?}) which does not match source {source:?}");
            return;
        }

        trace!("passed peer check, pushing to app side");

        if socket
            .recv_tx
            .try_push(UdpRecvMessage::Packet { source, payload })
            .is_ok()
            && let Some(wake) = socket.read_wake_handle.as_ref()
        {
            trace!("pushed packet to app side, waking now");
            wake.wake();
        } else {
            warn!(
                "we had a problem pushing to the app? or have no wake handle {:?}",
                socket.read_wake_handle
            );
        }
    }

    pub fn process_buffers(&mut self, ctx: &mut InterfaceContext) {
        trace!(
            "process buffers ready={:?}",
            self.ready_bits
                .iter()
                .map(|x| format!("{:b}", x.load(Ordering::Relaxed)))
                .collect::<Vec<_>>()
        );
        for ready in self.socket_ids.iter_by_ready_bits(&self.ready_bits) {
            trace!("ready is {:?}", ready);
            if let Some(socket) = self.sockets.get_mut(ready) {
                match socket.drain_send(ctx) {
                    DrainSendAction::NoAction => {}
                    DrainSendAction::Remove => {
                        self.sockets.remove(ready);
                    }
                }
            }
        }
    }
}

enum DrainSendAction {
    NoAction,
    Remove,
}

#[derive(Debug, Error)]
enum UdpSendError {
    #[error("Payload too large")]
    PayloadTooLarge,
    #[error("No route to host")]
    NetworkUnreachable,
    #[error("Host unreachable")]
    HostUnreachable,
    #[error("Other error")]
    Other,
}
type UdpSendResult = core::result::Result<(), UdpSendError>;

impl From<UdpSendError> for UdpSendResult {
    fn from(value: UdpSendError) -> Self {
        Err(value)
    }
}

#[derive(Debug, Default)]
struct SharableUdpSendResult {
    state: AtomicU32,
}

impl SharableUdpSendResult {
    pub fn store(&self, result: UdpSendResult) {
        let value = match result {
            Ok(()) => u32::MAX,
            Err(err) => {
                let (code, params): (u8, u32) = match err {
                    UdpSendError::PayloadTooLarge => (0x1, 0),
                    UdpSendError::NetworkUnreachable => (0x2, 0),
                    UdpSendError::HostUnreachable => (0x3, 0),
                    UdpSendError::Other => (0xff, 0),
                };

                params << u8::BITS | u32::from(code)
            }
        };
        self.state.store(value, Ordering::Release);
    }

    pub fn reset(&self) -> Option<UdpSendResult> {
        let value = self.state.swap(0, Ordering::Acquire);
        if value == 0 {
            return None;
        }
        if value == u32::MAX {
            return Some(Ok(()));
        }

        #[allow(clippy::cast_possible_truncation)]
        // Truncation to u8 is intentional as the u8 holds the error code
        Some(match value as u8 {
            0x1 => Err(UdpSendError::PayloadTooLarge),
            0x2 => Err(UdpSendError::NetworkUnreachable),
            0x3 => Err(UdpSendError::HostUnreachable),
            0xff => Err(UdpSendError::Other),
            _ => unreachable!("this should be unreachable unless a cosmic ray event did a thing"),
        })
    }
}

enum UdpConnectError {
    NoRouteToHost,
    NoAddress,
    InvalidAddress,
}
type UdpConnectResult = core::result::Result<(), UdpConnectError>;

#[derive(Debug)]
struct UdpSocketSharedState {
    send_result: SharableUdpSendResult,

    connected_to: RwLock<Option<SocketAddr>>,
    is_nonblocking: AtomicBool,
    allow_broadcast: AtomicBool,
    max_payload_size: AtomicUsize,
}

enum UdpSendMessage {
    NonBlocking {
        destination: SocketAddr,
        payload: bytes::Bytes,
    },
    Blocking {
        destination: SocketAddr,
        payload: bytes::Bytes,
        thread: std::thread::Thread,
    },
    UpdateReadWakeHandle(ReadWakeHandle),
    UpdateWriteWakeHandle(WakeHandle),
    Connect(
        Vec<SocketAddr>,
        std::sync::oneshot::Sender<UdpConnectResult>,
    ),
    Drop,
}

enum UdpRecvMessage {
    Packet {
        source: SocketAddr,
        payload: bytes::Bytes,
    },
}

struct UdpSocketHandle {
    recv_tx: ringbuf::HeapProd<UdpRecvMessage>,
    send_rx: ringbuf::HeapCons<UdpSendMessage>,

    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,

    shared_state: Arc<UdpSocketSharedState>,

    read_wake_handle: Option<ReadWakeHandle>,
    write_wake_handle: Option<WakeHandle>,
}

impl Debug for UdpSocketHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocketHandle")
            .field("recv_tx", &"ringbuf::HeapProd<UdpRecvMessage>")
            .field("send_rx", &"ringbuf::HeapCons<UdpSendMessage>")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("shared_state", &self.shared_state)
            .field("read_wake_handle", &self.read_wake_handle)
            .field("write_wake_handle", &self.write_wake_handle)
            .finish()
    }
}

impl UdpSocketHandle {
    fn connect(&mut self, ctx: &InterfaceContext, potentials: Vec<SocketAddr>) -> UdpConnectResult {
        let mut last_result: UdpConnectResult = Err(UdpConnectError::NoAddress);
        for potential in potentials {
            match potential.ip() {
                IpAddr::V4(v4) => {
                    if ctx.ipv4_route_table.lookup(v4).is_some() {
                        self.peer_addr = Some(potential);
                        self.shared_state
                            .connected_to
                            .write()
                            .expect("UDPSocket.shared_state.connected_to poisoned")
                            .replace(potential);

                        return Ok(());
                    }

                    last_result = Err(UdpConnectError::NoRouteToHost);
                }
                IpAddr::V6(_) => {
                    // TODO Impl IPv6
                    last_result = Err(UdpConnectError::InvalidAddress);
                }
            }
        }

        last_result
    }

    fn send_ipv4(
        ctx: &mut InterfaceContext,
        source: SocketAddrV4,
        destination: SocketAddrV4,
        payload: bytes::Bytes,
    ) -> SendResult {
        let source_ip = match source.ip() {
            &Ipv4Addr::UNSPECIFIED => {
                if let Some(route) = ctx.ipv4_route_table.lookup(*destination.ip()) {
                    route.source
                } else {
                    return Err(SendError::NoRouteToHost);
                }
            }
            a => *a,
        };

        let mut header = UdpHeader::new(
            source.port(),
            destination.port(),
            payload
                .len()
                .try_into()
                .expect("payload size is larger than u16"),
        );

        header.compute_and_update_checksum_v4(&source_ip, destination.ip(), &payload);

        IPv4Handler::send(
            ctx,
            source_ip,
            *destination.ip(),
            IPProtocolTypes::UDP,
            (header, payload),
        )
    }

    fn send_ipv6(
        ctx: &mut InterfaceContext,
        source: SocketAddrV6,
        destination: SocketAddrV6,
        payload: bytes::Bytes,
    ) -> SendResult {
        todo!("implement udp over ipv6 {ctx:?} {source:?} {destination:?} {payload:?}");
    }

    fn send_datagram(
        &self,
        ctx: &mut InterfaceContext,
        destination: SocketAddr,
        payload: bytes::Bytes,
    ) -> UdpSendResult {
        if let Err(err) = match (self.local_addr, destination) {
            (SocketAddr::V4(s), SocketAddr::V4(d)) => Self::send_ipv4(ctx, s, d, payload),
            (SocketAddr::V6(s), SocketAddr::V6(d)) => Self::send_ipv6(ctx, s, d, payload),
            // how the hell did we get here? just drop it
            _ => Ok(()),
        } {
            match err {
                SendError::PayloadTooLarge { max_size } => {
                    self.shared_state
                        .max_payload_size
                        .store(max_size - UdpHeader::LENGTH, Ordering::Release);

                    UdpSendError::PayloadTooLarge
                }
                SendError::BufferFull => UdpSendError::Other,
                SendError::PayloadTooShort => {
                    unreachable!("to get here we would have needed to not send our header")
                }
                SendError::NoRouteToHost => UdpSendError::NetworkUnreachable,
                SendError::ArpResolveBufferFull | SendError::ArpTimeout => {
                    UdpSendError::HostUnreachable
                }
            }
            .into()
        } else {
            Ok(())
        }
    }

    fn send_datagram_blocking(
        &self,
        ctx: &mut InterfaceContext,
        destination: SocketAddr,
        payload: bytes::Bytes,
        thread: &std::thread::Thread,
    ) {
        trace!("send_datagram_blocking {destination:?} {payload:?}");
        let result = self.send_datagram(ctx, destination, payload);
        trace!("send_datagram_blocking {result:?}");
        self.shared_state.send_result.store(result);
        thread.unpark();
    }

    fn send_datagram_nonblocking(
        &self,
        ctx: &mut InterfaceContext,
        destination: SocketAddr,
        payload: bytes::Bytes,
    ) {
        trace!("send_datagram_nonblocking {destination:?} {payload:?}");
        if let Err(err) = self.send_datagram(ctx, destination, payload) {
            match err {
                UdpSendError::PayloadTooLarge | UdpSendError::Other => {} // udp we don't signal drops
                UdpSendError::NetworkUnreachable | UdpSendError::HostUnreachable => {
                    self.shared_state.send_result.store(Err(err));
                }
            }
        }

        if !self.send_rx.is_full()
            && let Some(write_wake) = &self.write_wake_handle
        {
            write_wake.wake();
        }
    }

    pub fn drain_send(&mut self, ctx: &mut InterfaceContext) -> DrainSendAction {
        while let Some(message) = self.send_rx.try_pop() {
            match message {
                UdpSendMessage::NonBlocking {
                    destination,
                    payload,
                } => self.send_datagram_nonblocking(ctx, destination, payload),
                UdpSendMessage::Blocking {
                    destination,
                    payload,
                    thread,
                } => self.send_datagram_blocking(ctx, destination, payload, &thread),
                UdpSendMessage::UpdateReadWakeHandle(handle) => {
                    trace!("updated read wake handle");
                    _ = self.read_wake_handle.replace(handle);
                    if !self.recv_tx.is_empty() {
                        self.read_wake_handle
                            .as_mut()
                            .expect("we just set this 2 lines ago")
                            .wake();
                    }
                }
                UdpSendMessage::UpdateWriteWakeHandle(handle) => {
                    _ = self.write_wake_handle.replace(handle);
                    if !self.send_rx.is_full() {
                        self.write_wake_handle
                            .as_ref()
                            .expect("we just set this 2 lines ago")
                            .wake();
                    }
                }
                UdpSendMessage::Connect(peer, reply) => _ = reply.send(self.connect(ctx, peer)),
                UdpSendMessage::Drop => return DrainSendAction::Remove,
            }
        }

        DrainSendAction::NoAction
    }
}

#[derive(Debug)]
enum ReadWakeHandle {
    Poller(WakeHandle),
    Local(std::thread::Thread),
}
impl ReadWakeHandle {
    fn wake(&self) {
        match self {
            Self::Poller(wake_handle) => wake_handle.wake(),
            Self::Local(thread) => thread.unpark(),
        }
    }
}

pub struct UdpSocketContext {
    recv_rx: ringbuf::HeapCons<UdpRecvMessage>,
    send_tx: ringbuf::HeapProd<UdpSendMessage>,

    buffer_pool: BufferPool<WriteTrackingBuffer>,
    thread_handle: std::thread::Thread,
    ready_bits: Arc<[AtomicU64; 16]>,
    socket_id: usize,
}

impl UdpSocketContext {}

impl Debug for UdpSocketContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocket")
            .field("recv_rx", &"ringbuf::HeapProd<UdpRecvMessage>")
            .field("send_tx", &"ringbuf::HeapProd<UdpSendMessage>")
            .field("buffer_pool", &self.buffer_pool)
            .field("thread_handle", &self.thread_handle)
            .field("ready_bits", &self.ready_bits)
            .field("socket_id", &self.socket_id)
            .finish()
    }
}

#[derive(Debug)]
pub struct UdpSocket {
    socket_addr: SocketAddr,
    shared_state: Arc<UdpSocketSharedState>,
    context: UdpSocketContext,
}

impl UdpSocket {
    /// Receives a single datagram message on the socket. On success, returns the number
    /// of bytes read and the origin.
    ///
    /// The function must be called with valid byte array `buf` of sufficient size to
    /// hold the message bytes. If a message is too long to fit in the supplied buffer,
    /// excess bytes may be discarded.
    ///
    /// Refer to the platform-specific documentation on this function; it is considered
    /// correct for its behavior to differ from [`UdpSocket::recv`] if the underlying system
    /// call does so.
    ///
    /// [see std implementation](std::net::UdpSocket::recv_from)
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let non_blocking = self.load_non_blocking_and_check_errors()?;

        trace!("recv_from {non_blocking:?}");

        if let Some(value) = self.context.try_pop(buf) {
            return Ok(value);
        }
        trace!("recv_from nothing currently");

        if non_blocking {
            return Err(ErrorKind::WouldBlock.into());
        }

        trace!("recv_from registering to be awoken");
        self.context.register_self_for_wake()?;

        loop {
            trace!("recv_from checking for data");
            if let Some(value) = self.context.try_pop(buf) {
                return Ok(value);
            }

            trace!("and parking");
            std::thread::park();
        }
    }

    /// Receives a single datagram message on the socket, without removing it from the
    /// queue. On success, returns the number of bytes read and the origin.
    ///
    /// The function must be called with valid byte array `buf` of sufficient size to
    /// hold the message bytes. If a message is too long to fit in the supplied buffer,
    /// excess bytes may be discarded.
    ///
    /// Successive calls return the same data. This is accomplished by passing
    /// `MSG_PEEK` as a flag to the underlying `recvfrom` system call.
    ///
    /// Do not use this function to implement busy waiting, instead use `libc::poll` to
    /// synchronize IO events on one or more sockets.
    ///
    /// [see std implementation](std::net::UdpSocket::peek_from)
    pub fn peek_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let non_blocking = self.load_non_blocking_and_check_errors()?;

        if let Some(value) = self.context.try_peek(buf) {
            return Ok(value);
        }

        if non_blocking {
            return Err(ErrorKind::WouldBlock.into());
        }

        self.context.register_self_for_wake()?;

        loop {
            if let Some(value) = self.context.try_peek(buf) {
                return Ok(value);
            }

            std::thread::park();
        }
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written. Note that the operating system may refuse
    /// buffers larger than 65507. However, partial writes are not possible
    /// until buffer sizes above `i32::MAX`.
    ///
    /// Address type can be any implementor of [`ToSocketAddrs`] trait. See its
    /// documentation for concrete examples.
    ///
    /// It is possible for `addr` to yield multiple addresses, but `send_to`
    /// will only send data to the first address yielded by `addr`.
    ///
    /// This will return an error when the IP version of the local socket
    /// does not match that returned from [`ToSocketAddrs`].
    ///
    /// See [Issue #34202] for more details.
    ///
    /// [see std implementation](std::net::UdpSocket::send_to)
    pub fn send_to<A: ToSocketAddrs>(&mut self, buf: &[u8], addr: A) -> Result<usize> {
        let non_blocking = self.load_non_blocking_and_check_errors()?;

        trace!("send_to {non_blocking:?}");

        let destination = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid address"))?;

        trace!("send_to {destination:?}");

        match (self.socket_addr, destination) {
            (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_)) => {}
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "address version does not match",
                ));
            }
        }

        if non_blocking {
            trace!("sending non-blocking");
            self.context.send_inner(buf, destination, false)
        } else {
            trace!("sending blocking");
            self.send_to_blocking(buf, destination)
        }
    }

    /// Returns the socket address of the remote peer this socket was connected to.
    ///
    /// If the socket isn't connected, it will return a [`NotConnected`] error.
    ///
    /// [see std implementation](std::net::UdpSocket::peer_addr)
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        let connected_to = self
            .shared_state
            .connected_to
            .read()
            .map_err(|_| Error::other("shared state poisoned"))?;

        connected_to.map_or_else(
            || Err(Error::new(ErrorKind::NotConnected, "not connected")),
            Ok,
        )
    }

    /// Returns the socket address that this socket was created from.
    ///
    /// [see std implementation](std::net::UdpSocket::local_addr)
    pub const fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket_addr)
    }

    /// Sets the value of the `SO_BROADCAST` option for this socket.
    ///
    /// When enabled, this socket is allowed to send packets to a broadcast
    /// address.
    ///
    /// [see std implementation](std::net::UdpSocket::set_broadcast)
    pub fn set_broadcast(&self, enabled: bool) -> Result<()> {
        self.shared_state
            .allow_broadcast
            .store(enabled, Ordering::Release);
        Ok(())
    }

    /// Gets the value of the `SO_BROADCAST` option for this socket.
    ///
    /// For more information about this option, see [`UdpSocket::set_broadcast`].
    ///
    /// [see std implementation](std::net::UdpSocket::broadcast)
    pub fn broadcast(&self) -> Result<bool> {
        Ok(self.shared_state.allow_broadcast.load(Ordering::Acquire))
    }

    /// Connects this UDP socket to a remote address, allowing the `send` and
    /// `recv` syscalls to be used to send data and also applies filters to only
    /// receive data from the specified address.
    ///
    /// If `addr` yields multiple addresses, `connect` will be attempted with
    /// each of the addresses until the underlying OS function returns no
    /// error. Note that usually, a successful `connect` call does not specify
    /// that there is a remote server listening on the port, rather, such an
    /// error would only be detected after the first send. If the OS returns an
    /// error for each of the specified addresses, the error returned from the
    /// last connection attempt (the last address) is returned.
    ///
    /// [see std implementation](std::net::UdpSocket::connect)
    pub fn connect<A: ToSocketAddrs>(&mut self, addr: A) -> Result<()> {
        let (tx, rx) = std::sync::oneshot::channel();
        self.context
            .try_push(UdpSendMessage::Connect(
                addr.to_socket_addrs()?.collect(),
                tx,
            ))
            .map_err(|_| Error::other("failed to send connect control message"))?;

        match rx
            .recv()
            .map_err(|_| Error::other("failed to receive connect message"))?
        {
            Ok(()) => Ok(()),
            Err(UdpConnectError::NoRouteToHost) => Err(Error::new(
                ErrorKind::NetworkUnreachable,
                "no route to host",
            )),
            Err(UdpConnectError::InvalidAddress) => Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid or unsupported address",
            )),
            Err(UdpConnectError::NoAddress) => {
                Err(Error::new(ErrorKind::InvalidInput, "no address in input"))
            }
        }
    }

    /// Sends data on the socket to the remote address to which it is connected.
    /// On success, returns the number of bytes written. Note that the operating
    /// system may refuse buffers larger than 65507. However, partial writes are
    /// not possible until buffer sizes above `i32::MAX`.
    ///
    /// [`UdpSocket::connect`] will connect this socket to a remote address. This
    /// method will fail if the socket is not connected.
    ///
    /// [see std implementation](std::net::UdpSocket::send)
    pub fn send(&mut self, buf: &[u8]) -> Result<usize> {
        let peer = self.peer_addr()?;

        if self.shared_state.is_nonblocking.load(Ordering::Acquire) {
            self.context.send_inner(buf, peer, false)
        } else {
            self.send_to_blocking(buf, peer)
        }
    }

    /// Receives a single datagram message on the socket from the remote address to
    /// which it is connected. On success, returns the number of bytes read.
    ///
    /// The function must be called with valid byte array `buf` of sufficient size to
    /// hold the message bytes. If a message is too long to fit in the supplied buffer,
    /// excess bytes may be discarded.
    ///
    /// [`UdpSocket::connect`] will connect this socket to a remote address. This
    /// method will fail if the socket is not connected.
    ///
    /// [see std implementation](std::net::UdpSocket::recv)
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let peer = self.peer_addr()?;

        loop {
            let (count, source) = self.recv_from(buf)?;
            if source == peer {
                return Ok(count);
            }
        }
    }

    /// Receives single datagram on the socket from the remote address to which it is
    /// connected, without removing the message from input queue. On success, returns
    /// the number of bytes peeked.
    ///
    /// The function must be called with valid byte array `buf` of sufficient size to
    /// hold the message bytes. If a message is too long to fit in the supplied buffer,
    /// excess bytes may be discarded.
    ///
    /// Successive calls return the same data. This is accomplished by passing
    /// `MSG_PEEK` as a flag to the underlying `recv` system call.
    ///
    /// Do not use this function to implement busy waiting, instead use `libc::poll` to
    /// synchronize IO events on one or more sockets.
    ///
    /// [`UdpSocket::connect`] will connect this socket to a remote address. This
    /// method will fail if the socket is not connected.
    ///
    /// # Errors
    ///
    /// This method will fail if the socket is not connected. The `connect` method
    /// will connect this socket to a remote address.
    ///
    /// [see std implementation](std::net::UdpSocket::peek)
    pub fn peek(&mut self, buf: &mut [u8]) -> Result<usize> {
        let peer = self.peer_addr()?;

        loop {
            let (count, source) = self.peek_from(buf)?;
            if source == peer {
                return Ok(count);
            }
            // Consume/discard the bad/uninteresting packet
            _ = self.recv_from(buf)?;
        }
    }

    /// Moves this UDP socket into or out of nonblocking mode.
    ///
    /// This will result in `recv`, `recv_from`, `send`, and `send_to` system
    /// operations becoming nonblocking, i.e., immediately returning from their
    /// calls. If the IO operation is successful, `Ok` is returned and no
    /// further action is required. If the IO operation could not be completed
    /// and needs to be retried, an error with kind
    /// [`io::ErrorKind::WouldBlock`] is returned.
    ///
    /// [see std implementation](std::net::UdpSocket::set_nonblocking)
    pub fn set_nonblocking(&self, enabled: bool) -> Result<()> {
        self.shared_state
            .is_nonblocking
            .store(enabled, Ordering::Release);
        Ok(())
    }
}

impl UdpSocket {
    fn load_non_blocking_and_check_errors(&self) -> Result<bool> {
        let non_blocking = self.shared_state.is_nonblocking.load(Ordering::Acquire);

        if non_blocking && let Some(Err(err)) = self.shared_state.send_result.reset() {
            match err {
                UdpSendError::PayloadTooLarge | UdpSendError::Other => {} // these should not be set on this path
                UdpSendError::NetworkUnreachable => {
                    return Err(ErrorKind::NetworkUnreachable.into());
                }
                UdpSendError::HostUnreachable => {
                    return Err(ErrorKind::HostUnreachable.into());
                }
            }
        }

        Ok(non_blocking)
    }

    fn send_to_blocking(&mut self, buf: &[u8], destination: SocketAddr) -> Result<usize> {
        let written = self.context.send_inner(buf, destination, true)?;

        let result = loop {
            if let Some(result) = self.shared_state.send_result.reset() {
                break result;
            }

            std::thread::park();
        };

        match result {
            Ok(()) => Ok(written),
            Err(UdpSendError::PayloadTooLarge) => {
                Err(Error::new(ErrorKind::InvalidInput, "payload too large"))
            }
            Err(UdpSendError::Other) => {
                Err(Error::new(ErrorKind::OutOfMemory, "network buffer full"))
            }
            Err(UdpSendError::NetworkUnreachable) => Err(Error::new(
                ErrorKind::NetworkUnreachable,
                "no route to host",
            )),
            Err(UdpSendError::HostUnreachable) => {
                Err(Error::new(ErrorKind::HostUnreachable, "host unreachable"))
            }
        }
    }
}

impl UdpSocketContext {
    fn try_pop(&mut self, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        if let Some(UdpRecvMessage::Packet { source, payload }) = self.recv_rx.try_pop() {
            let copy_len = std::cmp::min(buf.len(), payload.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            return Some((copy_len, source));
        }

        None
    }

    fn try_peek(&self, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        if let Some(UdpRecvMessage::Packet { source, payload }) = self.recv_rx.try_peek() {
            let copy_len = std::cmp::min(buf.len(), payload.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            return Some((copy_len, *source));
        }

        None
    }

    fn try_push(&mut self, message: UdpSendMessage) -> std::result::Result<(), UdpSendMessage> {
        self.send_tx.try_push(message)?;

        let slice_index = self.socket_id / u64::BITS as usize;
        let bit_index = self.socket_id % u64::BITS as usize;

        trace!(
            "pushing message to ringbuf and setting [{}][{}] ready",
            slice_index, bit_index
        );
        self.ready_bits[slice_index].fetch_or(1 << bit_index, Ordering::Release);

        self.thread_handle.unpark();

        Ok(())
    }

    fn send_inner(&mut self, buf: &[u8], destination: SocketAddr, blocking: bool) -> Result<usize> {
        if buf.len() > self.buffer_pool.buffer_size() {
            return Err(Error::new(ErrorKind::InvalidInput, "buffer too large"));
        }

        let Some(mut buffer) = self.buffer_pool.acquire() else {
            return Err(Error::new(ErrorKind::OutOfMemory, "buffer pool exhausted"));
        };

        buffer[..buf.len()].copy_from_slice(buf);
        buffer.advance(buf.len());
        let written = buffer.len();
        let payload = bytes::Bytes::from_owner(buffer);

        Self::try_push(
            self,
            if blocking {
                UdpSendMessage::Blocking {
                    destination,
                    payload,
                    thread: std::thread::current(),
                }
            } else {
                UdpSendMessage::NonBlocking {
                    destination,
                    payload,
                }
            },
        )
        .map_err(|_| Error::new(ErrorKind::OutOfMemory, "failed to push packet to ringbuf"))?;

        Ok(written)
    }

    fn register_self_for_wake(&mut self) -> Result<()> {
        self.try_push(UdpSendMessage::UpdateReadWakeHandle(ReadWakeHandle::Local(
            std::thread::current(),
        )))
        .map_err(|_| {
            Error::new(
                ErrorKind::OutOfMemory,
                "could not send wait handle to network handler",
            )
        })?;

        Ok(())
    }
}

impl PollerReadRegister for UdpSocket {
    fn register_read(&mut self, handle: WakeHandle) -> Result<()> {
        self.context
            .try_push(UdpSendMessage::UpdateReadWakeHandle(
                ReadWakeHandle::Poller(handle),
            ))
            .map_err(|_| {
                Error::new(
                    ErrorKind::OutOfMemory,
                    "failed to push wake handle to handler",
                )
            })?;
        Ok(())
    }
}

impl PollerWriteRegister for UdpSocket {
    fn register_write(&mut self, handle: WakeHandle) -> Result<()> {
        self.context
            .try_push(UdpSendMessage::UpdateWriteWakeHandle(handle))
            .map_err(|_| {
                Error::new(
                    ErrorKind::OutOfMemory,
                    "failed to push wake handle to handler",
                )
            })?;
        Ok(())
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        _ = self.context.try_push(UdpSendMessage::Drop);
    }
}

trait ToUnspecified {
    fn to_unspecified(&self) -> IpAddr;
}
impl ToUnspecified for IpAddr {
    fn to_unspecified(&self) -> IpAddr {
        match self {
            Self::V4(_) => Self::V4(Ipv4Addr::UNSPECIFIED),
            Self::V6(_) => Self::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
}
