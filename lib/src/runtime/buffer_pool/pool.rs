use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

#[derive(Debug)]
struct BufferEntry {
    bytes: Vec<u8>,
    return_tx: std::sync::mpsc::Sender<Self>,
}

#[derive(Debug)]
pub struct BufferPool<T: From<PooledBuffer>> {
    return_tx: std::sync::mpsc::Sender<BufferEntry>,
    return_rx: std::sync::mpsc::Receiver<BufferEntry>,

    buffer_size: usize,
    capacity: usize,
    queue: std::collections::VecDeque<BufferEntry>,

    _marker: PhantomData<T>,
}

impl<T: From<PooledBuffer>> BufferPool<T> {
    /// Create a new `BufferPool` with capacity buffers of size
    pub fn new(size: usize, capacity: usize) -> Self {
        let (return_tx, return_rx) = std::sync::mpsc::channel();

        let mut queue = std::collections::VecDeque::with_capacity(capacity);
        for _ in 0..capacity {
            queue.push_back(BufferEntry {
                bytes: vec![0u8; size],
                return_tx: return_tx.clone(),
            });
        }

        Self {
            return_tx,
            return_rx,
            buffer_size: size,
            capacity,
            queue,
            _marker: PhantomData,
        }
    }

    pub fn acquire(&mut self) -> Option<T> {
        if let Some(buffer) = self.queue.pop_front() {
            return Some(
                PooledBuffer {
                    buffer: buffer.into(),
                }
                .into(),
            );
        }
        while let Ok(bytes) = self.return_rx.try_recv() {
            self.queue.push_back(bytes);
        }
        if let Some(buffer) = self.queue.pop_front() {
            return Some(
                PooledBuffer {
                    buffer: buffer.into(),
                }
                .into(),
            );
        }
        None
    }

    pub fn expand(&mut self, additional_capacity: usize) {
        self.capacity += additional_capacity;

        for _ in 0..additional_capacity {
            self.queue.push_back(BufferEntry {
                bytes: vec![0u8; self.buffer_size],
                return_tx: self.return_tx.clone(),
            });
        }
    }

    pub const fn buffer_size(&self) -> usize {
        self.buffer_size
    }
}

pub struct PooledBuffer {
    buffer: Option<BufferEntry>,
}

impl Debug for PooledBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuffer")
            .field("buffer", &self.as_slice())
            .finish()
    }
}

impl PooledBuffer {
    pub fn as_slice(&self) -> &[u8] {
        &self
            .buffer
            .as_ref()
            .expect("PooledBuffer read after Drop")
            .bytes
    }
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self
            .buffer
            .as_mut()
            .expect("PooledBuffer read after Drop")
            .bytes
    }
}

impl Deref for PooledBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_slice_mut()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        let entry = self.buffer.take().expect("PooledBuffer used after Drop");
        let return_tx = entry.return_tx.clone();

        // Commented to avoid memory bandwidth spamming
        // Zero out what has been written in for safety
        //entry.bytes[..self.written].fill(0);

        _ = return_tx.send(entry);
    }
}
