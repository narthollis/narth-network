use crate::runtime::interface::InterfaceContext;
use ringbuf::traits::Split;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};

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
    pub fn bind(&mut self, addr: SocketAddr) -> Result<UdpSocket> {
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

        let shared_state = Arc::new(UdpSocketSharedState::default());

        let handle = UdpSocketHandle {
            recv_tx,
            send_rx,
            allow_broadcast: false,
            connected_to: None,
            socket_id,
            shared_state: shared_state.clone(),
        };
        let socket = UdpSocket {
            recv_rx,
            send_tx,
            socket_id,
            thread_handle: std::thread::current(),
            is_nonblocking: AtomicBool::new(false),
            shared_state,
            ready_bits: self.ready_bits.clone(),
        };

        self.sockets.insert(addr, handle);

        Ok(socket)
    }

    pub fn recv(&mut self, source_addr: IpAddr, destination_addr: IpAddr, bytes: &bytes::Bytes) {
        todo!()
    }

    pub fn handle_send(&mut self, ctx: &mut InterfaceContext) {
        todo!("work out which of our sockets need sending and send stuff")
    }
}

#[derive(Debug, Default)]
struct UdpSocketSharedState {
    recv_waker: Mutex<Option<std::thread::Thread>>,
}

enum UdpSendMessage {}
enum UdpRecvMessage {}

struct UdpSocketHandle {
    recv_tx: ringbuf::HeapProd<UdpRecvMessage>,
    send_rx: ringbuf::HeapCons<UdpSendMessage>,
    allow_broadcast: bool,
    connected_to: Option<SocketAddr>,
    socket_id: usize,
    shared_state: Arc<UdpSocketSharedState>,
}

impl Debug for UdpSocketHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocketHandle")
            .field("recv_tx", &"ringbuf::HeapProd<UdpRecvMessage>")
            .field("send_rx", &"ringbuf::HeapCons<UdpSendMessage>")
            .field("allow_broadcast", &self.allow_broadcast)
            .field("connected_to", &self.connected_to)
            .field("socket_id", &self.socket_id)
            .field("shared_state", &self.shared_state)
            .finish()
    }
}

pub struct UdpSocket {
    recv_rx: ringbuf::HeapCons<UdpRecvMessage>,
    send_tx: ringbuf::HeapProd<UdpSendMessage>,
    socket_id: usize,
    thread_handle: std::thread::Thread,
    is_nonblocking: AtomicBool,
    shared_state: Arc<UdpSocketSharedState>,
    ready_bits: Arc<[AtomicU64; 16]>,
}

impl Debug for UdpSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocket")
            .field("recv_rx", &"ringbuf::HeapProd<UdpRecvMessage>")
            .field("send_tx", &"ringbuf::HeapProd<UdpSendMessage>")
            .field("socket_id", &self.socket_id)
            .field("thread_handle", &self.thread_handle)
            .field("is_nonblocking", &self.is_nonblocking)
            .field("shared_state", &self.shared_state)
            .field("ready_bits", &self.ready_bits)
            .finish()
    }
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
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        todo!()
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
    pub fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> Result<usize> {
        todo!()
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
    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        todo!()
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
        self.is_nonblocking
            .store(enabled, std::sync::atomic::Ordering::Release);
        Ok(())
    }
}
