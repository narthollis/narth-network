use crate::poller::{PollerReadRegister, PollerWriteRegister, WakeHandle};
use crate::protocols::ethernet::EthernetHeader;
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header};
use crate::protocols::udp::UdpHeader;
use crate::ready_by_bits::IterReadyByBits;
use crate::runtime::buffer_pool::{BufferPool, WriteTrackingBuffer};
use crate::runtime::interface::l3_ipv4::IPv4Handler;
use crate::runtime::interface::{InterfaceContext, SendResult};
use crate::write_to_buffer::WriteToBuffer;
use ringbuf::consumer::Consumer;
use ringbuf::traits::{Observer, Producer, Split};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

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

        let shared_state = Arc::new(UdpSocketSharedState {
            send_result: Mutex::default(),

            connected_to: RwLock::default(),

            allow_broadcast: AtomicBool::new(false),
            is_nonblocking: AtomicBool::new(false),
            mtu: AtomicU32::new(
                ctx.mtu
                    .try_into()
                    .expect("mtu is somehow bigger than u32 when it shouldn't be larger than u16"),
            ),
        });

        let handle = UdpSocketHandle {
            recv_tx,
            send_rx,
            connected_to: None,
            shared_state: shared_state.clone(),
            socket_addr: addr,
            read_wake_handle: None,
            write_wake_handle: None,
        };
        let socket = UdpSocket {
            context: UdpSocketContext {
                recv_rx,
                send_tx,
                buffer_pool: BufferPool::new(
                    // TODO adjust size if IPv6
                    ctx.mtu
                        - EthernetHeader::MAX_LENGTH
                        - IPv4Header::MIN_LENGTH
                        - UdpHeader::LENGTH,
                    64,
                ),
                thread_handle: std::thread::current(),
                ready_bits: self.ready_bits.clone(),
                socket_id,
            },
            socket_addr: addr,
            shared_state,
        };

        self.sockets.insert(addr, handle);

        Ok(socket)
    }

    pub fn recv(&mut self, source_addr: IpAddr, destination_addr: IpAddr, bytes: &bytes::Bytes) {
        let udp_header = match UdpHeader::from_bytes(bytes) {
            Ok(udp_header) => udp_header,
            _ => return,
        };

        let payload = bytes.slice(udp_header.encoded_length()..udp_header.encoded_length());

        match (source_addr, destination_addr) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                if !udp_header.validate_checksum_v4(&source, &destination, &payload) {
                    return;
                }
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                todo!("validate udp6 {source:?} {destination:?}")
            }
            _ => return, // Miss-matched address kinds
        };

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

        if let Ok(_) = socket.recv_tx.try_push(UdpRecvMessage::Packet {
            source: SocketAddr::new(source_addr, udp_header.source_port()),
            payload,
        }) && let Some(wake) = socket.read_wake_handle.as_ref()
        {
            wake.wake();
        }
    }

    pub fn process_buffers(&mut self, ctx: &mut InterfaceContext) {
        for ready in self.socket_ids.iter_by_ready_bits(&self.ready_bits) {
            if let Some(socket) = self.sockets.get_mut(ready) {
                socket.drain_send(ctx);
            }
        }
    }
}

#[derive(Debug)]
struct UdpSocketSharedState {
    send_result: Mutex<Option<SendResult>>,

    connected_to: RwLock<Option<SocketAddr>>,
    is_nonblocking: AtomicBool,
    allow_broadcast: AtomicBool,
    mtu: AtomicU32,
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

    connected_to: Option<SocketAddr>,
    shared_state: Arc<UdpSocketSharedState>,
    socket_addr: SocketAddr,

    read_wake_handle: Option<ReadWakeHandle>,
    write_wake_handle: Option<WakeHandle>,
}

impl Debug for UdpSocketHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocketHandle")
            .field("recv_tx", &"ringbuf::HeapProd<UdpRecvMessage>")
            .field("send_rx", &"ringbuf::HeapCons<UdpSendMessage>")
            .field("connected_to", &self.connected_to)
            .field("shared_state", &self.shared_state)
            .field("socket_addr", &self.socket_addr)
            .finish()
    }
}

impl UdpSocketHandle {
    fn send_ipv4(
        ctx: &mut InterfaceContext,
        source: SocketAddrV4,
        destination: SocketAddrV4,
        payload: &bytes::Bytes,
    ) -> SendResult {
        let mut header = UdpHeader::new(
            source.port(),
            destination.port(),
            payload
                .len()
                .try_into()
                .expect("payload size didn't is larger than u16"),
        );
        header.compute_and_update_checksum_v4(source.ip(), destination.ip(), payload);

        IPv4Handler::send(
            ctx,
            destination.ip(),
            source.ip(),
            IPProtocolTypes::UDP,
            &(header, payload),
        )
    }

    fn send_ipv6(
        ctx: &mut InterfaceContext,
        source: SocketAddrV6,
        destination: SocketAddrV6,
        payload: &bytes::Bytes,
    ) -> SendResult {
        todo!("implement udp over ipv6 {ctx:?} {source:?} {destination:?} {payload:?}");
    }

    fn send_datagram(
        &self,
        ctx: &mut InterfaceContext,
        destination: SocketAddr,
        payload: bytes::Bytes,
    ) -> SendResult {
        match (self.socket_addr, destination) {
            (SocketAddr::V4(s), SocketAddr::V4(d)) => Self::send_ipv4(ctx, s, d, &payload),
            (SocketAddr::V6(s), SocketAddr::V6(d)) => Self::send_ipv6(ctx, s, d, &payload),
            // how the hell did we get here? just drop it
            _ => Ok(()),
        }
    }

    fn send_datagram_blocking(
        &self,
        ctx: &mut InterfaceContext,
        destination: SocketAddr,
        payload: bytes::Bytes,
        thread: std::thread::Thread,
    ) {
        let result = self.send_datagram(ctx, destination, payload);
        // If the lock is poisoned carry on - not a lot we can do
        if let Ok(mut lock) = self.shared_state.send_result.lock() {
            *lock = Some(result);
        }
        thread.unpark();
    }

    pub fn drain_send(&mut self, ctx: &mut InterfaceContext) {
        while let Some(message) = self.send_rx.try_pop() {
            match message {
                UdpSendMessage::NonBlocking {
                    destination,
                    payload,
                } => {
                    _ = self.send_datagram(ctx, destination, payload);
                    if !self.send_rx.is_full()
                        && let Some(write_wake) = &self.write_wake_handle
                    {
                        write_wake.wake();
                    }
                }
                UdpSendMessage::Blocking {
                    destination,
                    payload,
                    thread,
                } => self.send_datagram_blocking(ctx, destination, payload, thread),
                UdpSendMessage::UpdateReadWakeHandle(handle) => {
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
            }
        }
    }
}

enum ReadWakeHandle {
    Poller(WakeHandle),
    Local(std::thread::Thread),
}
impl ReadWakeHandle {
    fn wake(&self) {
        match self {
            ReadWakeHandle::Poller(wake_handle) => wake_handle.wake(),
            ReadWakeHandle::Local(thread) => thread.unpark(),
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
        if let Some(UdpRecvMessage::Packet { source, payload }) = self.context.recv_rx.try_pop() {
            let copy_len = std::cmp::min(buf.len(), payload.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            return Ok((copy_len, source));
        }

        if self.shared_state.is_nonblocking.load(Ordering::Acquire) {
            return Err(ErrorKind::WouldBlock.into());
        }

        self.context
            .try_push(UdpSendMessage::UpdateReadWakeHandle(ReadWakeHandle::Local(
                std::thread::current(),
            )))
            .map_err(|_| {
                Error::new(
                    ErrorKind::OutOfMemory,
                    "could not send wait handle to network handler",
                )
            })?;

        loop {
            if let Some(UdpRecvMessage::Packet { source, payload }) = self.context.recv_rx.try_pop()
            {
                let copy_len = std::cmp::min(buf.len(), payload.len());
                buf[..copy_len].copy_from_slice(&payload[..copy_len]);
                return Ok((copy_len, source));
            }

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
    pub fn peek_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        todo!()
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
    ///
    /// # Panics
    ///
    /// This will panic if in blocking mode the shared mutex with UdpManager has been posied
    pub fn send_to<A: ToSocketAddrs>(&mut self, buf: &[u8], addr: A) -> Result<usize> {
        let destination = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid address"))?;
        match (self.socket_addr, destination) {
            (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_)) => {}
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "address version does not match",
                ));
            }
        }

        if self.shared_state.is_nonblocking.load(Ordering::Acquire) {
            self.context.send_inner(buf, destination, false)
        } else {
            self.send_to_blocking(buf, destination)
        }
    }

    /// Returns the socket address of the remote peer this socket was connected to.
    ///
    /// If the socket isn't connected, it will return a [`NotConnected`] error.
    ///
    /// [see std implementation](std::net::UdpSocket::peer_addr)
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        todo!()
    }

    /// Returns the socket address that this socket was created from.
    ///
    /// [see std implementation](std::net::UdpSocket::local_addr)
    pub fn local_addr(&self) -> Result<SocketAddr> {
        todo!()
    }

    /// Sets the value of the `SO_BROADCAST` option for this socket.
    ///
    /// When enabled, this socket is allowed to send packets to a broadcast
    /// address.
    ///
    /// [see std implementation](std::net::UdpSocket::set_broadcast)
    pub fn set_broadcast(&self, enabled: bool) -> Result<()> {
        todo!()
    }

    /// Gets the value of the `SO_BROADCAST` option for this socket.
    ///
    /// For more information about this option, see [`UdpSocket::set_broadcast`].
    ///
    /// [see std implementation](std::net::UdpSocket::broadcast)
    pub fn broadcast(&self) -> Result<bool> {
        todo!()
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
    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> Result<()> {
        todo!()
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
    ///
    /// # Panics
    ///
    /// This will panic if the shared state has been poisoned
    pub fn send(&mut self, buf: &[u8]) -> Result<usize> {
        let connected_to = *self
            .shared_state
            .connected_to
            .read()
            .expect("connected_to poisoned"); // We don't need to hold that read lock

        let Some(destination) = connected_to else {
            return Err(Error::new(ErrorKind::NotConnected, "socket not connected"));
        };

        if self.shared_state.is_nonblocking.load(Ordering::Acquire) {
            self.context.send_inner(buf, destination, false)
        } else {
            self.send_to_blocking(buf, destination)
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
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        todo!()
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
    pub fn peek(&self, buf: &mut [u8]) -> Result<usize> {
        todo!()
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
            .store(enabled, std::sync::atomic::Ordering::Release);
        Ok(())
    }
}

impl UdpSocket {
    fn send_to_blocking(&mut self, buf: &[u8], destination: SocketAddr) -> Result<usize> {
        let written = self.context.send_inner(buf, destination, true)?;

        let result = loop {
            let potential_result = self
                .shared_state
                .send_result
                .lock()
                .expect("send_waker poisoned")
                .take();

            if let Some(result) = potential_result {
                break result;
            }

            std::thread::park();
        };

        match result {
            Ok(()) => Ok(written),
            Err(err) => Err(Error::other(err)), // TODO improve this mapping
        }
    }
}

impl UdpSocketContext {
    fn try_push(&mut self, message: UdpSendMessage) -> std::result::Result<(), UdpSendMessage> {
        self.send_tx.try_push(message)?;

        let slice_index = self.socket_id / u64::BITS as usize;
        let bit_index = self.socket_id % u64::BITS as usize;

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
}

impl PollerReadRegister for UdpSocket {
    fn register_read(&mut self, handle: WakeHandle) -> Result<()> {
        self.context
            .send_tx
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
            .send_tx
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

trait Unspecified {
    fn to_unspecified(&self) -> IpAddr;
}
impl Unspecified for IpAddr {
    fn to_unspecified(&self) -> IpAddr {
        match self {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
}
