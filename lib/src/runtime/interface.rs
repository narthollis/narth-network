use crate::common::WriteToBuffer;
use crate::protocols::arp::{ArpMessage, ArpState, ArpTable, Operation};
use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use crate::protocols::ipv4::icmp::{
    DestinationUnreachableMessage, ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH, ICMPMessage,
    ICMPMessageTypes,
};
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header, prefix_to_mask};
use crate::runtime::address_table::AddressTable;
use crate::runtime::common::{NetworkSender, NetworkSenderError};
use crate::runtime::interface::AsyncSendError::LocalSendError;
use crate::runtime::interface::SendError::ArpTimeout;
use crate::runtime::route_table::{RouteInformation, RouteTable};
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Add;
use std::sync::{Arc, RwLock, mpsc, oneshot};
use tracing::{debug, error, info, trace, trace_span, warn};

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum Error {
    #[error("Failed to check address: {0}")]
    AddressCheckFailed(#[source] SendError),
    #[error("Address removed before add completed")]
    AddressRemoved,
    #[error("Address in use")]
    AddressInUse,

    #[error("Route Unknown Source")]
    RouteUnknownSource(),
    #[error("Route Next Hop Unreachable")]
    RouteNextHopUnreachable(),

    #[error("Failed read {0} from shared state")]
    SharedDataReadFailed(&'static str),

    #[error("Control send failed")]
    ControlFailed,
}

#[derive(thiserror::Error, Debug, Clone, Copy)]
pub enum SendError {
    #[error("Failed send: Payload too large")]
    PayloadTooLarge { max_size: usize },
    #[error("Failed send: Payload too small")]
    PayloadTooShort,
    #[error("Failed send: No Route to Host")]
    NoRouteToHost,
    #[error("Failed send: Buffer full")]
    BufferFull,
    #[error("Failed send: ARP Resolution buffer full")]
    ArpResolveBufferFull,
    #[error("Failed send: ARP Timeout")]
    ArpTimeout,
}
type SendResult = std::result::Result<(), SendError>;

#[derive(Debug, Copy, Clone)]
pub enum AsyncSendError {
    LocalSendError {
        error: SendError,
        ipv4header: IPv4Header,
        datagram: [u8; 8],
    },
    ICMPUnreachable(DestinationUnreachableMessage),
}

impl From<mpsc::SendError<InterfaceControlMessage>> for Error {
    fn from(_value: mpsc::SendError<InterfaceControlMessage>) -> Self {
        Self::ControlFailed
    }
}

type Result<T> = std::result::Result<T, Error>;
type ResultSender<T> = oneshot::Sender<Result<T>>;

pub(crate) enum InterfaceControlMessage {
    IPv4AddressAdd(Ipv4Addr, u8, ResultSender<()>),
    IPv4AddressRemove(Ipv4Addr),
    IPv4RouteAdd {
        target: Ipv4Addr,
        target_mask: Ipv4Addr,
        next_hop: Ipv4Addr,
        src: Option<Ipv4Addr>,
        reply: ResultSender<()>,
    },
    IPv4RouteRemove(),
    Ping {
        target: Ipv4Addr,
        count: Option<usize>,
        interval: std::time::Duration,
        reply: ResultSender<super::ping::PingSession>,
    },
    Stop(),
}

#[derive(Debug)]
pub struct Interface {
    control_tx: mpsc::SyncSender<InterfaceControlMessage>,
    ipv4_addresses: Arc<RwLock<Vec<(Ipv4Addr, Ipv4Addr)>>>,
    ipv4_routes: Arc<RwLock<Vec<RouteInformation<Ipv4Addr>>>>,
}

impl Interface {
    pub(super) fn new(
        mtu: usize,
        mac_address: MacAddr,
        network_tx: super::common::NetworkSender,
        network_rx: super::common::RingBufConsumer<super::common::NetworkRecvPayload>,
    ) -> (Self, InterfaceWorker) {
        let (control_tx, control_rx) = mpsc::sync_channel(10);

        let worker = InterfaceWorker::new(control_rx, network_tx, network_rx, mtu, mac_address);
        let interface = Self {
            control_tx,
            ipv4_addresses: worker.ipv4_addresses.shared(),
            ipv4_routes: worker.sender_context.ipv4_route_table.shared(),
        };

        (interface, worker)
    }

    pub fn stop(&self) -> Result<()> {
        self.control_tx
            .send(InterfaceControlMessage::Stop())
            .map_err(|_| Error::ControlFailed)
    }

    pub fn ping(
        &self,
        target: Ipv4Addr,
        count: Option<usize>,
        interval: Option<std::time::Duration>,
    ) -> Result<super::ping::PingSession> {
        let (tx, rx) = oneshot::channel();

        self.control_tx
            .send(InterfaceControlMessage::Ping {
                target,
                count,
                interval: interval.unwrap_or_else(|| std::time::Duration::from_secs(1)),
                reply: tx,
            })
            .map_err(|_| Error::ControlFailed)?;

        rx.recv().map_err(|_| Error::ControlFailed)?
    }

    pub fn ipv4_address_add(&self, addr: Ipv4Addr, prefix: u8) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.control_tx
            .send(InterfaceControlMessage::IPv4AddressAdd(addr, prefix, tx))?;

        rx.recv().unwrap_or_else(|e| {
            error!("Failed to unwrap mpsc recv: {e}");
            Err(Error::ControlFailed)
        })
    }
    pub fn ipv4_address_remove(&self, addr: Ipv4Addr) -> Result<()> {
        self.control_tx
            .send(InterfaceControlMessage::IPv4AddressRemove(addr))?;

        Ok(())
    }

    pub fn ipv4_addresses(&self) -> Result<Vec<Ipv4Addr>> {
        Ok(self
            .ipv4_addresses
            .read()
            .map_err(|_| Error::SharedDataReadFailed("ipv4_addresses"))?
            .iter()
            .map(|(addr, _)| *addr)
            .collect())
    }

    pub fn ipv4_route_add(
        &self,
        target: Ipv4Addr,
        prefix: u8,
        next_hop: Ipv4Addr,
        src: Option<Ipv4Addr>,
    ) -> Result<()> {
        let target_mask = prefix_to_mask(prefix);
        let target = target & target_mask;

        let (tx, rx) = oneshot::channel();

        self.control_tx
            .send(InterfaceControlMessage::IPv4RouteAdd {
                target,
                target_mask,
                next_hop,
                reply: tx,
                src,
            })?;

        rx.recv().unwrap_or(Err(Error::ControlFailed))
    }

    pub fn ipv4_routes(&self) -> Result<Vec<RouteInformation<Ipv4Addr>>> {
        Ok(self
            .ipv4_routes
            .read()
            .map_err(|_| Error::SharedDataReadFailed("ipv4_routes"))?
            .clone())
    }

    pub fn ipv6_addresses(&self) -> Result<Vec<Ipv6Addr>> {
        Ok(vec![])
    }
}

pub(crate) struct InterfaceWorker {
    control_rx: mpsc::Receiver<InterfaceControlMessage>,

    // network_tx: super::common::NetworkSender,
    network_rx: super::common::NetworkRecvReceiver,

    mtu: usize,
    mac_addr: MacAddr,

    ping_manager: super::ping::PingManager,

    // arp_table: ArpTable,
    ipv4_addresses: AddressTable<Ipv4Addr>,
    // ipv4_route_table: RouteTable<Ipv4Addr>,
    ipv4_pending_addresses: Vec<(Ipv4Addr, Ipv4Addr, ResultSender<()>)>,
    // ipv4_send_buffer: HashMap<Ipv4Addr, VecDeque<(IPv4Header, bytes::Bytes)>>,
    sender_context: SenderContext,
}

impl InterfaceWorker {
    const MAX_IPV4_PENDING_BUFFER_SIZE: usize = 5;

    pub(super) fn new(
        control_rx: mpsc::Receiver<InterfaceControlMessage>,
        network_tx: super::common::NetworkSender,
        network_rx: super::common::NetworkRecvReceiver,
        mtu: usize,
        mac_addr: MacAddr,
    ) -> Self {
        Self {
            control_rx,
            // network_tx,
            network_rx,
            mtu,
            mac_addr,

            ping_manager: super::ping::PingManager::default(),

            // arp_table: ArpTable::default(),
            ipv4_addresses: AddressTable::default(),
            // ipv4_route_table: RouteTable::default(),
            ipv4_pending_addresses: Vec::default(),
            // ipv4_send_buffer: HashMap::default(),
            sender_context: SenderContext {
                mac_addr,
                mtu,

                network_tx,
                arp_table: ArpTable::default(),
                ipv4_route_table: RouteTable::default(),
                ipv4_send_buffer: HashMap::default(),
            },
        }
    }

    pub fn run(&mut self) {
        info!(
            "Running interface {interface} worker",
            interface = self.mac_addr
        );

        loop {
            if !self.perform_control() {
                error!("Interface {} control closed", self.mac_addr);
                break;
            }
            loop {
                use ringbuf::traits::Consumer;

                match self.network_rx.try_pop() {
                    Some(super::common::NetworkRecvPayload::Packet(bytes)) => self.recv(bytes),
                    None => {
                        break;
                    }
                }
            }

            let deadline = self.perform_timers();

            std::thread::park_timeout(
                deadline.saturating_duration_since(std::time::Instant::now()),
            );
        }
        error!("Interface {} worker stopped", self.mac_addr);
    }

    fn perform_control(&mut self) -> bool {
        while let Ok(msg) = self.control_rx.try_recv() {
            match msg {
                InterfaceControlMessage::IPv4AddressAdd(addr, prefix, reply) => {
                    self.handle_ipv4_address_add(addr, prefix, reply);
                }
                InterfaceControlMessage::IPv4AddressRemove(addr) => {
                    self.handle_ipv4_address_remove(addr);
                }
                InterfaceControlMessage::IPv4RouteAdd {
                    target,
                    target_mask,
                    next_hop,
                    src,
                    reply,
                } => {
                    _ = reply.send(self.handle_ipv4_route_add(target, target_mask, next_hop, src));
                }
                InterfaceControlMessage::IPv4RouteRemove() => todo!(),
                InterfaceControlMessage::Ping {
                    target,
                    count,
                    interval,
                    reply,
                } => _ = reply.send(Ok(self.ping_manager.ping(target, count, interval))),
                InterfaceControlMessage::Stop() => {
                    return false;
                }
            }
        }

        if !self.ipv4_pending_addresses.is_empty() {
            use crate::protocols::arp::ArpState;

            for i in (0..self.ipv4_pending_addresses.len()).rev() {
                match self
                    .sender_context
                    .arp_table
                    .request(self.ipv4_pending_addresses[i].0, Ipv4Addr::UNSPECIFIED)
                {
                    ArpState::PendingWait { .. } => {}
                    ArpState::PendingRetry { .. }
                    | ArpState::ResolvedStale(_)
                    | ArpState::Restart => {
                        if let Err(err) = self.sender_context.send_arp_request(
                            self.ipv4_pending_addresses[i].0,
                            Ipv4Addr::UNSPECIFIED,
                        ) {
                            let (_, _, reply) = self.ipv4_pending_addresses.remove(i);
                            _ = reply.send(Err(Error::AddressCheckFailed(err)));
                        }
                    }
                    ArpState::Timeout => {
                        let (addr, mask, reply) = self.ipv4_pending_addresses.remove(i);
                        self.ipv4_addresses.insert(addr, mask);
                        self.sender_context.ipv4_route_table.insert_or_update(
                            addr & mask,
                            mask,
                            addr,
                            None,
                        );
                        _ = reply.send(Ok(()));
                        _ = self.sender_context.send_gratuitous_arp(addr);
                    }
                    ArpState::Resolved(_) => {
                        let (_, _, reply) = self.ipv4_pending_addresses.remove(i);
                        _ = reply.send(Err(Error::AddressInUse));
                    }
                }
            }
        }

        true
    }

    fn handle_ipv4_address_add(&mut self, addr: Ipv4Addr, prefix: u8, reply: ResultSender<()>) {
        if let Err(err) = self
            .sender_context
            .send_arp_request(addr, Ipv4Addr::UNSPECIFIED)
        {
            _ = reply.send(Err(Error::AddressCheckFailed(err)));

            return;
        }

        self.ipv4_pending_addresses
            .push((addr, prefix_to_mask(prefix), reply));
    }

    fn handle_ipv4_address_remove(&mut self, addr: Ipv4Addr) {
        // iterate in reverse order so we don't end up with shifting index shenanigans
        for i in (0..self.ipv4_pending_addresses.len()).rev() {
            if self.ipv4_pending_addresses[i].0 == addr {
                let (_, _, reply) = self.ipv4_pending_addresses.remove(i);
                _ = reply.send(Err(Error::AddressRemoved));
            }
        }

        self.sender_context
            .ipv4_route_table
            .remove_matching(|x| x.source == addr);
        self.ipv4_addresses.remove(&addr);
    }

    fn handle_ipv4_route_add(
        &mut self,
        target: Ipv4Addr,
        target_mask: Ipv4Addr,
        next_hop: Ipv4Addr,
        src: Option<Ipv4Addr>,
    ) -> Result<()> {
        let src = src
            .or_else(|| self.ipv4_addresses.first_with_subnet_containing(&next_hop))
            .ok_or(Error::RouteNextHopUnreachable())
            .and_then(|src| {
                if self.ipv4_addresses.contains(&src) {
                    Ok(src)
                } else {
                    Err(Error::RouteUnknownSource())
                }
            })?;

        self.sender_context.ipv4_route_table.insert_or_update(
            target,
            target_mask,
            src,
            Some(next_hop),
        );

        Ok(())
    }

    fn perform_timers(&mut self) -> std::time::Instant {
        let arp_deadline = self.perform_arp_timers();
        let icmp_deadline = self.ping_manager.perform_timers(&mut self.sender_context);

        [arp_deadline, icmp_deadline]
            .iter()
            .flatten()
            .min()
            .map_or_else(
                || std::time::Instant::now().add(std::time::Duration::from_secs(1)),
                |x| *x,
            )
    }

    fn perform_arp_timers(&mut self) -> Option<std::time::Instant> {
        let mut deadline: Option<std::time::Instant> = None;

        for (ip, source) in self.sender_context.arp_table.pending() {
            match self.sender_context.arp_table.request(ip, source) {
                ArpState::PendingWait {
                    deadline: request_deadline,
                } => {
                    deadline = deadline
                        .map(|dl| dl.min(request_deadline))
                        .or(Some(request_deadline));
                }
                ArpState::PendingRetry { source } => {
                    _ = self.sender_context.send_arp_request(ip, source);
                }
                // Look, I don't quite know how we would hit ResolvedStale here, but...
                ArpState::Resolved(mac) | ArpState::ResolvedStale(mac) => {
                    self.dequeue_pending_ipv4(mac, ip);
                    // TODO Whatever else is needed now the address has been resovled - not sure what that is
                }
                // Restart is when the Timeout has gone stale or the Resolved has gone through stale out the other side
                ArpState::Timeout | ArpState::Restart => {
                    if let Some(queue) = self.sender_context.ipv4_send_buffer.remove(&ip) {
                        for (ipv4header, payload) in queue {
                            self.forward_async_error(LocalSendError {
                                error: ArpTimeout,
                                ipv4header,
                                datagram: payload[..ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH]
                                    .try_into()
                                    .unwrap_or([0u8; 8]),
                            });
                        }
                    }
                }
            }
        }

        deadline
    }

    fn recv(&mut self, frame: bytes::Bytes) {
        let ethernet_header = match crate::protocols::ethernet::EthernetHeader::from_bytes(&frame) {
            Ok(ethernet_header) => ethernet_header,
            Err(e) => {
                debug!("failed to parse ethernet header: {}", e);
                return;
            }
        };
        let ethernet_payload = frame.slice(ethernet_header.encoded_length()..);

        trace_span!(
            "recv",
            ethernet_source = ethernet_header.source_address().to_string(),
            ethernet_destination = ethernet_header.destination_address().to_string(),
        );
        trace!("Incoming Ethernet header: {:?}", ethernet_header);

        match ethernet_header.ether_type() {
            EtherType::ARP => self.recv_arp(ethernet_payload),
            EtherType::IPv4 => self.recv_ipv4(ethernet_header, ethernet_payload),
            EtherType::IPv6 => {
                // TODO
            }
            t => debug!("unsupported ethernet type: {:?}", t),
        }
    }

    fn recv_arp(&mut self, bytes: bytes::Bytes) {
        let arp = match ArpMessage::from_bytes(&bytes) {
            Ok(arp) => arp,
            Err(e) => {
                debug!("failed to parse arp message: {}", e);
                return;
            }
        };
        trace!("Incoming ARP: {:?}", arp);

        // https://datatracker.ietf.org/doc/rfc826/ Packet Reception

        // Update the table ONLY IF the sender protocol already exits
        let mut merged = self
            .sender_context
            .arp_table
            .update_only(arp.source_mac(), arp.source_addr());

        if self.ipv4_addresses.contains(&arp.target_addr()) {
            if !merged {
                self.sender_context
                    .arp_table
                    .update_or_insert(arp.source_mac(), arp.source_addr());
                merged = true;
            }

            if arp.operation() == Operation::Request {
                let reply = arp.reply(self.mac_addr, arp.target_addr());
                if let Err(err) =
                    self.sender_context
                        .send_ethernet(reply.target_mac(), EtherType::ARP, &reply)
                {
                    // Sending the ARP Response - if this doesn't work not much we can do
                    error!("Failed to send ARP reply: {}", err);
                }
            }
        }

        if merged {
            self.dequeue_pending_ipv4(arp.source_mac(), arp.source_addr());
        }
    }

    fn recv_ipv4(&mut self, ethernet: EthernetHeader, bytes: bytes::Bytes) {
        let ip = match IPv4Header::from_bytes(&bytes) {
            Ok(ip) => ip,
            Err(e) => {
                debug!("failed to parse ipv4 header: {}", e);
                return;
            }
        };
        if ip.is_fragmented() {
            trace!("dropping fragmented IPv4");
            return;
        }

        let payload = &bytes.slice(ip.encoded_length()..ip.total_length());

        trace_span!(
            "recv ipv4",
            ipv4_source = ip.source_address().to_string(),
            ipv4_destination = ip.destination_address().to_string()
        );
        trace!("Incoming IPv4 header: {:?}", ip);

        let merged = self
            .sender_context
            .arp_table
            .update_or_insert(ethernet.source_address(), ip.source_address());
        let source_address = ip.source_address();

        match ip.protocol() {
            IPProtocolTypes::ICMP => self.recv_ipv4_icmp(ip, payload),
            IPProtocolTypes::UDP => {
                // todo udp
                // self.udp_manager.recv_ipv4(ip.source(), ip.destination(), payload);
            }
            IPProtocolTypes::TCP => {
                // todo tcp
            }
            IPProtocolTypes::Other(protocol) => {
                info!("Received IPv4 message for {protocol}");
                // protocol we don't care about so drop it
            }
        };

        if merged {
            self.dequeue_pending_ipv4(ethernet.source_address(), source_address);
        }
    }

    fn recv_ipv4_icmp(&mut self, ipv4_header: IPv4Header, payload: &bytes::Bytes) {
        let icmp = match ICMPMessage::from_bytes(payload) {
            Ok(icmp) => icmp,
            Err(e) => {
                debug!("failed to parse icmp message: {}", e);
                return;
            }
        };
        trace!("Incoming IPv4 ICMP: {:?}", icmp);

        match &icmp.message {
            ICMPMessageTypes::Echo(echo) => {
                let echo_reply = ICMPMessage::echo_reply(echo);

                // We don't really care if we fail to send the echo reply
                _ = self.sender_context.send_ipv4(
                    ipv4_header.source_address(),
                    ipv4_header.destination_address(),
                    IPProtocolTypes::ICMP,
                    &echo_reply,
                );
            }
            ICMPMessageTypes::EchoReply(reply) => {
                self.ping_manager.on_echo_reply(ipv4_header, reply);
            }
            ICMPMessageTypes::DestinationUnreachable(m) => {
                self.forward_async_error(AsyncSendError::ICMPUnreachable(*m))
            }
            _ => {
                // TODO we need to parse the identifying data out of the control message's data and then
                // forward it to the protocol manager
                eprintln!("CONTROL MESSAGE: {icmp:?}");
            }
        }
    }

    fn forward_async_error(&mut self, error: AsyncSendError) {
        let (header, datagram) = match &error {
            AsyncSendError::LocalSendError {
                ipv4header,
                datagram,
                ..
            } => (ipv4header, datagram),
            AsyncSendError::ICMPUnreachable(m) => (&m.ipv4header, &m.datagram),
        };

        match header.protocol() {
            IPProtocolTypes::ICMP => {
                let kind = datagram[0];
                let code = datagram[1];
                // let checksum = [unreachable.datagram[2], unreachable.datagram[3]];

                if kind == 8 {
                    self.ping_manager.on_async_send_error(error);
                } else {
                    warn!("ICMP unreachable for ICMP: {kind}/{code}");
                }
            }
            _ => {
                error!(
                    "Interface={interface} - Error={error:?}",
                    interface = self.mac_addr,
                    error = &error
                );
            }
        }
    }

    fn dequeue_pending_ipv4(&mut self, mac: MacAddr, ipv4addr: Ipv4Addr) {
        if let Some(queue) = self.sender_context.ipv4_send_buffer.remove(&ipv4addr) {
            trace!(
                "resolved {} draining {} pending messages",
                ipv4addr,
                queue.len()
            );

            for pending in queue {
                if let Err(error) =
                    self.sender_context
                        .send_ethernet(mac, EtherType::IPv4, &pending)
                {
                    self.forward_async_error(AsyncSendError::LocalSendError {
                        error,
                        ipv4header: pending.0,
                        // We should not have accepted an IPv4 message <8 bytes but hey
                        datagram: pending.1[0..8].try_into().unwrap_or([0u8; 8]),
                    })
                }
            }
        }
    }
}

impl std::fmt::Debug for InterfaceWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceWorker")
            .field("mtu", &self.mtu)
            .field("mac_addr", &self.mac_addr)
            .field("ping_manager", &self.ping_manager)
            .field("ipv4_addresses", &self.ipv4_addresses)
            .field("sender_context", &self.sender_context)
            .finish_non_exhaustive()
    }
}

impl Drop for InterfaceWorker {
    fn drop(&mut self) {
        // TODO consider if we need to pull this onto the general network control channel when we introduce that
        self.sender_context
            .network_tx
            .try_send(super::common::NetworkSendPayload::Closed(self.mac_addr))
            .expect("send closed");
    }
}

impl std::fmt::Display for InterfaceWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InterfaceWorker({})", self.mac_addr)
    }
}

#[derive(Debug)]
pub(super) struct SenderContext {
    mtu: usize,
    mac_addr: MacAddr,
    network_tx: NetworkSender,
    arp_table: ArpTable,
    ipv4_route_table: RouteTable<Ipv4Addr>,
    ipv4_send_buffer: HashMap<Ipv4Addr, VecDeque<(IPv4Header, bytes::Bytes)>>,
}

impl SenderContext {
    fn send(&mut self, packet: &impl WriteToBuffer) -> SendResult {
        trace!("sending packet");

        assert!(packet.encoded_length() <= self.mtu);

        let mut buffer = bytes::BytesMut::with_capacity(self.mtu);
        packet.write_to_buffer(&mut buffer);
        buffer.truncate(buffer.len());

        let buffer = buffer.freeze();

        if tracing::enabled!(tracing::Level::TRACE) {
            parse_and_log(&buffer);
        }

        match self
            .network_tx
            .try_send(super::common::NetworkSendPayload::Packet(buffer))
        {
            Ok(_) => Ok(()),
            Err(NetworkSenderError::WakeError(err)) => {
                error!("Failed to wake network for new packet: {err:?}");
                // We queued the message, but just failed to wake the network
                Ok(())
            }
            Err(NetworkSenderError::SendError { .. }) => Err(SendError::BufferFull),
        }
    }

    fn send_ethernet(
        &mut self,
        destination: MacAddr,
        ether_type: EtherType,
        payload: &impl WriteToBuffer,
    ) -> SendResult {
        let header = EthernetHeader::new(ether_type, self.mac_addr, destination);

        // Ethernet frames are caped at MTU - this should already be handled by Layer4, so I'm keeping the 'assert!' here
        assert!(header.encoded_length() + payload.encoded_length() <= self.mtu);

        self.send(&(header, payload))
    }

    pub fn send_ipv4(
        &mut self,
        destination: Ipv4Addr,
        source: Ipv4Addr,
        protocol: IPProtocolTypes,
        payload: &impl WriteToBuffer,
    ) -> SendResult {
        // ICMP requires the first 64 bits/8 bytes of the payload be included in control messages - so an IP frame
        // less than that should be considered mal-formed
        if payload.encoded_length() < 8 {
            return Err(SendError::PayloadTooShort);
        }
        // This is where we should do fragmentation if were supported it
        // I'm not going to support that, so sync-reject
        // TODO This is where we would handle the Path MTU lookup
        if (payload.encoded_length() + IPv4Header::MIN_LENGTH) > self.mtu {
            return Err(SendError::PayloadTooLarge {
                max_size: self.mtu - IPv4Header::MIN_LENGTH,
            });
        }

        let payload = {
            let mut buff = bytes::BytesMut::with_capacity(payload.encoded_length());
            payload.write_to_buffer(&mut buff);
            buff.freeze()
        };
        let payload_len: u16 = payload.len().try_into().expect("payload length overflow");

        let Some(route) = self.ipv4_route_table.lookup(destination) else {
            return Err(SendError::NoRouteToHost);
        };
        let source = source.or_unspecified(route.source);

        let header = IPv4Header::new(protocol, source, destination, payload_len);

        let next_hop = route.next_hop.unwrap_or(destination);

        let arp_state = self.arp_table.request(next_hop, source);
        trace!("arp table said {:?} for {}", arp_state, next_hop);

        // Check if we need to send an ARP request
        match arp_state {
            ArpState::PendingRetry { source } => self.send_arp_request(next_hop, source)?,
            ArpState::ResolvedStale(_) | ArpState::Restart => {
                self.send_arp_request(next_hop, source)?;
            }
            _ => {}
        }

        match arp_state {
            ArpState::PendingRetry { .. } | ArpState::PendingWait { .. } | ArpState::Restart => {
                trace!("so we buffer the message");
                let buff = self.ipv4_send_buffer.entry(next_hop).or_default();
                if buff.len() < InterfaceWorker::MAX_IPV4_PENDING_BUFFER_SIZE {
                    buff.push_back((header, payload));
                } else {
                    return Err(SendError::ArpResolveBufferFull);
                }
            }
            ArpState::Resolved(dest_mac) | ArpState::ResolvedStale(dest_mac) => {
                trace!("so we send the message");
                self.send_ethernet(dest_mac, EtherType::IPv4, &(header, payload))?;
            }
            ArpState::Timeout => {
                trace!("so we return arp timeout");
                return Err(SendError::ArpTimeout);
            }
        };

        Ok(())
    }

    fn send_gratuitous_arp(&mut self, ipv4addr: Ipv4Addr) -> SendResult {
        let arp = ArpMessage::gratuitous(self.mac_addr, ipv4addr);
        self.send_ethernet(arp.target_mac(), EtherType::ARP, &arp)
    }

    fn send_arp_request(&mut self, target_ipv4: Ipv4Addr, source_ipv4: Ipv4Addr) -> SendResult {
        // TODO maybe push this down into the ARP manger?
        if self.arp_table.can_send_request(target_ipv4, source_ipv4) {
            let arp = ArpMessage::request(self.mac_addr, target_ipv4, source_ipv4);

            self.send_ethernet(arp.target_mac(), EtherType::ARP, &arp)?;
        }

        Ok(())
    }
}

trait OrUnspecified {
    fn or_unspecified(self, other: Self) -> Self;
}
impl OrUnspecified for Ipv4Addr {
    fn or_unspecified(self, other: Self) -> Self {
        if self.is_unspecified() {
            return other;
        }
        self
    }
}

fn parse_and_log(rem: &bytes::Bytes) {
    // this next part should be behind some kind of debug
    let e = match EthernetHeader::from_bytes(rem) {
        Ok(e) => e,
        Err(e) => {
            error!("failed to parse outgoing ethernet header: {}", e);
            return;
        }
    };
    trace!("Outgoing ethernet header: {:?}", e);

    let rem = &rem.slice(e.encoded_length()..);

    match e.ether_type() {
        EtherType::ARP => {
            let a = match ArpMessage::from_bytes(rem) {
                Ok(a) => a,
                Err(e) => {
                    error!("failed to parse outgoing arp message: {}", e);
                    return;
                }
            };
            trace!("Outgoing arp message: {:?}", a);
        }
        EtherType::IPv4 => {
            let ip = match IPv4Header::from_bytes(rem) {
                Ok(ip) => ip,
                Err(e) => {
                    error!("failed to parse outgoing ipv4 header: {}", e);
                    return;
                }
            };
            trace!("Outgoing IPv4 header: {:?}", ip);
            let rem = &rem.slice(ip.encoded_length()..);
            match ip.protocol() {
                IPProtocolTypes::ICMP => {
                    let icmp = match ICMPMessage::from_bytes(rem) {
                        Ok(icmp) => icmp,
                        Err(e) => {
                            error!("failed to parse outgoing icmp message: {}", e);
                            return;
                        }
                    };
                    trace!("Outgoing ICMP message: {:?}", icmp);
                }
                IPProtocolTypes::UDP => {}
                _ => {}
            }
        }
        _ => {}
    }
}
