use crate::poller::WakeHandle;
use crate::protocols::ipv4::IPProtocolTypes;
use crate::protocols::udp::UdpHeader;
use crate::runtime::interface::l3_ipv4::IPv4Handler;
use crate::runtime::interface::l4_managers::udp::messages::{
    DrainSendAction, UdpConnectError, UdpConnectResult, UdpRecvMessage, UdpSendError,
    UdpSendMessage, UdpSendResult,
};
use crate::runtime::interface::l4_managers::udp::{ReadWakeHandle, UdpSocketSharedState};
use crate::runtime::interface::{InterfaceContext, SendError, SendResult};
use ringbuf::traits::{Consumer, Observer};
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::trace;

pub(super) struct UdpSocketHandle {
    pub recv_tx: ringbuf::HeapProd<UdpRecvMessage>,
    pub send_rx: ringbuf::HeapCons<UdpSendMessage>,

    pub local_addr: SocketAddr,
    pub peer_addr: Option<SocketAddr>,

    pub shared_state: Arc<UdpSocketSharedState>,

    pub read_wake_handle: Option<ReadWakeHandle>,
    pub write_wake_handle: Option<WakeHandle>,
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
    pub(crate) fn new(
        recv_tx: ringbuf::HeapProd<UdpRecvMessage>,
        send_rx: ringbuf::HeapCons<UdpSendMessage>,
        local_addr: SocketAddr,
        shared_state: Arc<UdpSocketSharedState>,
    ) -> Self {
        Self {
            recv_tx,
            send_rx,
            local_addr,
            peer_addr: None,
            shared_state,
            read_wake_handle: None,
            write_wake_handle: None,
        }
    }

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
