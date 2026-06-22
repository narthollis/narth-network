use crate::protocols::ipv4::IPv4Header;
use crate::protocols::udp::UdpHeader;
use crate::ready_by_bits::IterReadyByBits;
use crate::runtime::UdpSocket;
use crate::runtime::interface::InterfaceContext;
use crate::runtime::interface::l4_managers::udp::handle::UdpSocketHandle;
use crate::runtime::interface::l4_managers::udp::messages::{
    DrainSendAction, SharableUdpSendResult, UdpRecvMessage, UdpSendMessage,
};
use crate::runtime::interface::l4_managers::udp::port_binding::PortBindings;
use crate::runtime::interface::l4_managers::udp::{UdpSocketContext, UdpSocketSharedState};
use crate::write_to_buffer::WriteToBuffer;
use ringbuf::traits::{Producer, Split};
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tracing::{trace, trace_span, warn};

#[derive(Debug)]
pub struct UdpManager {
    sockets: PortBindings,
    ready_bits: Arc<[AtomicU64; 16]>,
    socket_ids: Box<[Option<SocketAddr>; u64::BITS as usize * 16]>,
}

impl Default for UdpManager {
    fn default() -> Self {
        Self {
            sockets: PortBindings::default(),
            ready_bits: Arc::default(),
            socket_ids: vec![Option::<SocketAddr>::None; u64::BITS as usize * 16]
                .into_boxed_slice()
                .try_into()
                .expect("the initialisation size didn't match the declared size"),
        }
    }
}

impl UdpManager {
    const MAX_EPHEMERAL_PORT_ATTEMPTS: usize = 128;

    pub fn bind(&mut self, ctx: &InterfaceContext, addr: SocketAddr) -> std::io::Result<UdpSocket> {
        if !addr.is_ipv4() {
            // For now reject any IPv6 stuff because we haven't implemented it
            return Err(Error::new(
                ErrorKind::Unsupported,
                "ipv6 is not yet supported",
            ));
        }

        let addr = if addr.port() == 0 {
            let mut attempts = 0;
            loop {
                let port = fastrand::u16(ctx.ephemeral_ports.clone());
                let proposed = SocketAddr::new(addr.ip(), port);
                if self.sockets.is_bindable(&proposed, false, true) {
                    break proposed;
                }
                attempts += 1;
                if attempts >= Self::MAX_EPHEMERAL_PORT_ATTEMPTS {
                    return Err(Error::new(
                        ErrorKind::AddrInUse,
                        "ephemeral ports exhausted",
                    ));
                }
            }
        } else if !self.sockets.is_bindable(&addr, false, true) {
            return Err(Error::new(ErrorKind::AddrInUse, "address already in use"));
        } else {
            addr
        };

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

        let handle = UdpSocketHandle::new(recv_tx, send_rx, addr, shared_state.clone());

        let socket = UdpSocket {
            context: UdpSocketContext::new(
                recv_rx,
                send_tx,
                payload_max_size,
                64,
                std::thread::current(),
                self.ready_bits.clone(),
                socket_id,
            ),
            socket_addr: addr,
            shared_state,
        };

        self.sockets.insert(addr, handle, true);

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
