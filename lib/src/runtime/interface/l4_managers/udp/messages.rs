use crate::poller::WakeHandle;
use crate::runtime::interface::l4_managers::udp::ReadWakeHandle;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use thiserror::Error;

pub(super) enum DrainSendAction {
    NoAction,
    Remove,
}

#[derive(Debug, Error)]
pub(super) enum UdpSendError {
    #[error("Payload too large")]
    PayloadTooLarge,
    #[error("No route to host")]
    NetworkUnreachable,
    #[error("Host unreachable")]
    HostUnreachable,
    #[error("Other error")]
    Other,
}
pub(super) type UdpSendResult = Result<(), UdpSendError>;

impl From<UdpSendError> for UdpSendResult {
    fn from(value: UdpSendError) -> Self {
        Err(value)
    }
}

#[derive(Debug, Default)]
pub(super) struct SharableUdpSendResult {
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

pub(super) enum UdpConnectError {
    NoRouteToHost,
    NoAddress,
    InvalidAddress,
}
pub(super) type UdpConnectResult = Result<(), UdpConnectError>;

pub(super) enum UdpSendMessage {
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

pub(super) enum UdpRecvMessage {
    Packet {
        source: SocketAddr,
        payload: bytes::Bytes,
    },
}
