use crate::runtime::buffer_pool::{BufferPool, WriteTrackingBuffer};
use crate::runtime::interface::l4_managers::udp::ReadWakeHandle;
use crate::runtime::interface::l4_managers::udp::messages::{UdpRecvMessage, UdpSendMessage};
use ringbuf::consumer::Consumer;
use ringbuf::producer::Producer;
use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::trace;

pub(super) struct UdpSocketContext {
    recv_rx: ringbuf::HeapCons<UdpRecvMessage>,
    send_tx: ringbuf::HeapProd<UdpSendMessage>,

    buffer_pool: BufferPool<WriteTrackingBuffer>,
    thread_handle: std::thread::Thread,
    ready_bits: Arc<[AtomicU64; 16]>,
    socket_id: usize,
}

impl Debug for UdpSocketContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocket")
            .field("recv_rx", &"ringbuf::HeapProd<UdpRecvMessage>")
            .field("send_tx", &"ringbuf::HeapProd<UdpSendMessage>")
            .field("buffer_pool", &self.buffer_pool)
            .field("thread_handle", &self.thread_handle)
            .field("ready_bits", &self.ready_bits)
            .field("socket_id", &self.socket_id)
            .finish()
    }
}

impl UdpSocketContext {
    pub(crate) fn new(
        recv_rx: ringbuf::HeapCons<UdpRecvMessage>,
        send_tx: ringbuf::HeapProd<UdpSendMessage>,
        payload_max_size: usize,
        buffer_pool_size: usize,
        thread_handle: std::thread::Thread,
        ready_bits: Arc<[AtomicU64; 16]>,
        socket_id: usize,
    ) -> Self {
        Self {
            recv_rx,
            send_tx,
            buffer_pool: BufferPool::new(payload_max_size, buffer_pool_size),
            thread_handle,
            ready_bits,
            socket_id,
        }
    }

    pub fn try_pop(&mut self, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        if let Some(UdpRecvMessage::Packet { source, payload }) = self.recv_rx.try_pop() {
            let copy_len = std::cmp::min(buf.len(), payload.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            return Some((copy_len, source));
        }

        None
    }

    pub fn try_peek(&self, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        if let Some(UdpRecvMessage::Packet { source, payload }) = self.recv_rx.try_peek() {
            let copy_len = std::cmp::min(buf.len(), payload.len());
            buf[..copy_len].copy_from_slice(&payload[..copy_len]);
            return Some((copy_len, *source));
        }

        None
    }

    pub fn try_push(&mut self, message: UdpSendMessage) -> std::result::Result<(), UdpSendMessage> {
        self.send_tx.try_push(message)?;

        let slice_index = self.socket_id / u64::BITS as usize;
        let bit_index = self.socket_id % u64::BITS as usize;

        trace!(
            "pushing message to ringbuf and setting [{}][{}] ready",
            slice_index, bit_index
        );
        self.ready_bits[slice_index].fetch_or(1 << bit_index, Ordering::Release);

        self.thread_handle.unpark();

        Ok(())
    }

    pub fn send_inner(
        &mut self,
        buf: &[u8],
        destination: SocketAddr,
        blocking: bool,
    ) -> std::io::Result<usize> {
        if buf.len() > self.buffer_pool.buffer_size() {
            return Err(Error::new(ErrorKind::InvalidInput, "buffer too large"));
        }

        let Some(mut buffer) = self.buffer_pool.acquire() else {
            return Err(Error::new(ErrorKind::OutOfMemory, "buffer pool exhausted"));
        };

        buffer[..buf.len()].copy_from_slice(buf);
        buffer.advance(buf.len());
        let written = buffer.len();
        let payload = bytes::Bytes::from_owner(buffer);

        Self::try_push(
            self,
            if blocking {
                UdpSendMessage::Blocking {
                    destination,
                    payload,
                    thread: std::thread::current(),
                }
            } else {
                UdpSendMessage::NonBlocking {
                    destination,
                    payload,
                }
            },
        )
        .map_err(|_| Error::new(ErrorKind::OutOfMemory, "failed to push packet to ringbuf"))?;

        Ok(written)
    }

    pub(crate) fn register_self_for_wake(&mut self) -> std::io::Result<()> {
        self.try_push(UdpSendMessage::UpdateReadWakeHandle(ReadWakeHandle::Local(
            std::thread::current(),
        )))
        .map_err(|_| {
            Error::new(
                ErrorKind::OutOfMemory,
                "could not send wait handle to network handler",
            )
        })?;

        Ok(())
    }
}
