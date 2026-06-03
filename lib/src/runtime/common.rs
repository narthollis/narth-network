use crate::protocols::ethernet::EthernetHeader;
use crate::protocols::ethernet::mac::MacAddr;
use std::io;

pub(super) const NETWORK_WAKE_TOKEN: mio::Token = mio::Token(0);
pub(super) const BRIDGE_WAKE_TOKEN: mio::Token = mio::Token(1);

#[derive(Debug, Clone)]
pub enum NetworkSendPayload {
    Packet(bytes::Bytes),
    Listen(MacAddr, NetworkSender<NetworkRecvPayload>),
    Closed(MacAddr),
}

#[derive(Debug, Clone)]
pub enum NetworkRecvPayload {
    Packet(bytes::Bytes),
}

#[derive(thiserror::Error, Debug)]
pub(super) enum NetworkSenderError<T> {
    #[error(transparent)]
    TryRecvError(#[from] std::sync::mpsc::SendError<T>),
    #[error(transparent)]
    WakeError(#[from] io::Error),
}

#[derive(Debug, Clone)]
pub(super) struct NetworkSender<T> {
    waker: std::sync::Arc<mio::Waker>,
    send_sender: std::sync::mpsc::Sender<T>,
}

impl<T> NetworkSender<T> {
    pub(super) fn new(
        waker: std::sync::Arc<mio::Waker>,
        send_sender: std::sync::mpsc::Sender<T>,
    ) -> Self {
        Self { waker, send_sender }
    }

    pub(super) fn send(&self, payload: T) -> Result<(), NetworkSenderError<T>> {
        self.send_sender.send(payload)?;
        self.waker.wake()?;

        Ok(())
    }
}
