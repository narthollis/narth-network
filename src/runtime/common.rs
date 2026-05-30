use crate::protocols::ethernet::EthernetHeader;
use crate::protocols::ethernet::mac::MacAddr;
use std::io;
use std::sync::{mpsc, oneshot};

pub enum NetworkSendPayload {
    Packet(bytes::Bytes, oneshot::Sender<io::Result<usize>>),
    Closed(MacAddr),
}
pub enum NetworkRecvPayload {
    Packet(EthernetHeader, bytes::Bytes),
}

pub struct NetworkHandle {
    pub send: mpsc::Sender<NetworkSendPayload>,
    pub recv: mpsc::Receiver<NetworkRecvPayload>,
}
