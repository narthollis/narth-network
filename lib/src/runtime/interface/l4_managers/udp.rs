mod context;
mod handle;
pub mod manager;
mod messages;
mod port_binding;

use crate::poller::{PollerReadRegister, PollerWriteRegister, WakeHandle};
use crate::runtime::emsgsize::errmsgsize;
use crate::runtime::interface::l4_managers::udp::context::UdpSocketContext;
use crate::runtime::interface::l4_managers::udp::messages::{
    SharableUdpSendResult, UdpConnectError, UdpSendError, UdpSendMessage,
};
use std::fmt::Debug;
use std::io::{Error, ErrorKind, Result};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tracing::trace;

pub use manager::UdpManager;

#[derive(Debug)]
struct UdpSocketSharedState {
    send_result: SharableUdpSendResult,

    connected_to: RwLock<Option<SocketAddr>>,
    is_nonblocking: AtomicBool,
    allow_broadcast: AtomicBool,
    max_payload_size: AtomicUsize,
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
        if buf.len() > self.shared_state.max_payload_size.load(Ordering::Acquire) {
            return Err(errmsgsize());
        }

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

        self.send_to(buf, peer)
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
