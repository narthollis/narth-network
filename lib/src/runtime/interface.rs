mod interface_worker;
mod sender_context;

use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ipv4::icmp::DestinationUnreachableMessage;
use crate::protocols::ipv4::{IPv4Header, prefix_to_mask};
pub(crate) use crate::runtime::interface::interface_worker::InterfaceWorker;
pub(crate) use crate::runtime::interface::sender_context::SenderContext;
use crate::runtime::route_table::RouteInformation;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock, mpsc, oneshot};
use tracing::error;

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
