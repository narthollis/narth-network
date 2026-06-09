mod pool;

pub use pool::{BufferPool, PooledBuffer};

#[derive(Debug)]
pub struct WriteTrackingBuffer {
    buffer: PooledBuffer,
    written: usize,
}

impl WriteTrackingBuffer {
    pub const fn advance(&mut self, written: usize) {
        self.written += written;
    }
}

impl From<PooledBuffer> for WriteTrackingBuffer {
    fn from(buffer: PooledBuffer) -> Self {
        Self { buffer, written: 0 }
    }
}

impl AsRef<[u8]> for WriteTrackingBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buffer[..self.written]
    }
}

impl std::ops::Deref for WriteTrackingBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer[..self.written]
    }
}

impl std::ops::DerefMut for WriteTrackingBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer[self.written..]
    }
}
