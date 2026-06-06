use crate::protocols::ethernet::mac::MacAddr;
use std::io;

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
    #[error(transparent)]
    TryRecvError(#[from] std::sync::mpsc::SendError<T>),
    #[error(transparent)]
    WakeError(#[from] io::Error),
}

// TODO internal stuff should be thread::park and thread::unpark

#[derive(Debug, Clone)]
pub(super) struct NetworkSender {
    waker: std::sync::Arc<mio::Waker>,
    send_sender: std::sync::mpsc::Sender<NetworkSendPayload>,
}

impl NetworkSender {
    pub(super) const fn new(
        waker: std::sync::Arc<mio::Waker>,
        send_sender: std::sync::mpsc::Sender<NetworkSendPayload>,
    ) -> Self {
        Self { waker, send_sender }
    }

    pub(super) fn send(
        &self,
        payload: NetworkSendPayload,
    ) -> Result<(), NetworkSenderError<NetworkSendPayload>> {
        self.send_sender.send(payload)?;
        self.waker.wake()?;

        Ok(())
    }
}

pub type RingBufProducer<T> = ringbuf::HeapProd<T>;
pub type RingBufConsumer<T> = ringbuf::HeapCons<T>;
