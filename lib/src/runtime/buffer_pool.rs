struct BufferEntry {
    bytes: Vec<u8>,
    return_tx: std::sync::mpsc::Sender<Self>,
}
pub struct BufferPool {
    return_tx: std::sync::mpsc::Sender<BufferEntry>,
    return_rx: std::sync::mpsc::Receiver<BufferEntry>,

    size: usize,
    capacity: usize,
    queue: std::collections::VecDeque<BufferEntry>,
}

impl BufferPool {
    /// Create a new BufferPool with capacity buffers of size
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
            size,
            capacity,
            queue,
        }
    }

    pub fn pop(&mut self) -> Option<LocalBuffer> {
        if let Some(buffer) = self.queue.pop_front() {
            return Some(LocalBuffer {
                buffer: buffer.into(),
                written: 0,
            });
        }
        while let Ok(bytes) = self.return_rx.try_recv() {
            self.queue.push_back(bytes);
        }
        if let Some(buffer) = self.queue.pop_front() {
            return Some(LocalBuffer {
                buffer: buffer.into(),
                written: 0,
            });
        }
        None
    }

    pub fn expand(&mut self, additional_capacity: usize) {
        self.capacity += additional_capacity;

        for _ in 0..additional_capacity {
            self.queue.push_back(BufferEntry {
                bytes: vec![0u8; self.size],
                return_tx: self.return_tx.clone(),
            });
        }
    }
}

pub struct LocalBuffer {
    buffer: Option<BufferEntry>,
    written: usize,
}

impl LocalBuffer {
    pub const fn advance(&mut self, written: usize) {
        self.written += written;
    }
}

impl AsRef<[u8]> for LocalBuffer {
    fn as_ref(&self) -> &[u8] {
        &self
            .buffer
            .as_ref()
            .expect("LocalBuffer in unexpected state during read")
            .bytes[..self.written]
    }
}

impl std::ops::Deref for LocalBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self
            .buffer
            .as_ref()
            .expect("LocalBuffer in unexpected state during read")
            .bytes[..self.written]
    }
}

impl std::ops::DerefMut for LocalBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self
            .buffer
            .as_mut()
            .expect("LocalBuffer in unexpected state during write")
            .bytes[self.written..]
    }
}

impl Drop for LocalBuffer {
    fn drop(&mut self) {
        let mut entry = self
            .buffer
            .take()
            .expect("LocalBuffer in unexpected state during drop");
        let return_tx = entry.return_tx.clone();

        // Zero out what has been written in for safety
        entry.bytes[..self.written].fill(0);

        _ = return_tx.send(entry);
    }
}
