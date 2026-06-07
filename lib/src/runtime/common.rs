use crate::protocols::ethernet::mac::MacAddr;
use std::fmt::{Debug, Formatter};
use std::io;
use std::sync::atomic::Ordering;

pub(super) const NETWORK_WAKE_TOKEN: mio::Token = mio::Token(0);
pub(super) const BRIDGE_WAKE_TOKEN: mio::Token = mio::Token(1);

#[derive(Debug)]
pub enum NetworkSendPayload {
    Packet(bytes::Bytes),
    Closed(MacAddr),
}

#[derive(Debug)]
pub enum NetworkRecvPayload {
    Packet(bytes::Bytes),
}
pub type NetworkRecvReceiver = RingBufConsumer<NetworkRecvPayload>;
pub type NetworkRecvSender = RingBufProducer<NetworkRecvPayload>;

#[derive(thiserror::Error, Debug)]
pub(super) enum NetworkSenderError<T> {
    #[error("failed to write to ringbuf")]
    SendError { payload: T },
    #[error(transparent)]
    WakeError(#[from] io::Error),
}

pub(super) struct NetworkSender {
    waker: std::sync::Arc<mio::Waker>,
    send_sender: RingBufProducer<NetworkSendPayload>,
    ready_bits: std::sync::Arc<[std::sync::atomic::AtomicU64; 4]>,
    id: u8,
}

impl NetworkSender {
    pub(super) const fn new(
        waker: std::sync::Arc<mio::Waker>,
        send_sender: RingBufProducer<NetworkSendPayload>,
        ready_bits: std::sync::Arc<[std::sync::atomic::AtomicU64; 4]>,
        id: u8,
    ) -> Self {
        Self {
            waker,
            send_sender,
            ready_bits,
            id,
        }
    }

    pub(super) fn try_send(
        &mut self,
        payload: NetworkSendPayload,
    ) -> Result<(), NetworkSenderError<NetworkSendPayload>> {
        use ringbuf::traits::Producer;
        if let Err(payload) = self.send_sender.try_push(payload) {
            return Err(NetworkSenderError::SendError { payload });
        }

        // Find out which of the slices we are in (ie. 0-63=0, 64-127=1 etc.)
        let slice_idx = (u32::from(self.id) / u64::BITS) as usize;
        let bit_idx = u32::from(self.id) % u64::BITS;
        self.ready_bits[slice_idx].fetch_or(1 << bit_idx, Ordering::Release);
        self.waker.wake()?;

        Ok(())
    }
}

impl Debug for NetworkSender {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkSender")
            .field("id", &self.id)
            .field("send_sender", &"ringbuf::Produce<NetworkSendPayload>")
            .field("ready_bits", &self.ready_bits)
            .field("waker", &self.waker)
            .finish()
    }
}

pub type RingBufProducer<T> = ringbuf::HeapProd<T>;
pub type RingBufConsumer<T> = ringbuf::HeapCons<T>;
