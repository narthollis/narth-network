use std::cmp::Ordering;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Weak as ArcWeak};
use std::thread::Thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug)]
struct SharedState {
    dropped: AtomicBool,
}

#[derive(Debug)]
pub struct Token {
    id: usize,
    shared_state: Arc<SharedState>,
}
impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for Token {}
impl Hash for Token {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        self.shared_state
            .dropped
            .store(true, AtomicOrdering::Release);
    }
}

#[derive(Debug)]
pub struct WakeHandle {
    bits: Arc<AtomicU64>,
    index: u8,
    thread: Thread,
    shared_state: Arc<SharedState>,
}

impl WakeHandle {
    pub fn wake(&self) {
        if !self.shared_state.dropped.load(AtomicOrdering::Acquire) {
            self.bits.fetch_or(1 << self.index, AtomicOrdering::Release);
            self.thread.unpark();
        }
    }

    #[must_use]
    pub fn is_token_dropped(&self) -> bool {
        self.shared_state.dropped.load(AtomicOrdering::Acquire)
    }
}

#[derive(Debug, Default)]
struct ReadyBitShared {
    read: Arc<AtomicU64>,
    write: Arc<AtomicU64>,
}

#[derive(Debug, Default)]
struct TargetTracker {
    token: Weak<Token>,
    shared: ArcWeak<SharedState>,
}

#[derive(Debug)]
pub struct Poller {
    targets: Vec<Option<TargetTracker>>,
    ready_bits: Vec<ReadyBitShared>,
    thread: Thread,

    // Marks Poller as being !Send + !Sync forcing it to be tied to the tread it was constructed on
    _marker: PhantomData<*mut ()>,
}

impl Default for Poller {
    fn default() -> Self {
        Self {
            targets: Vec::default(),

            ready_bits: Vec::default(),

            thread: std::thread::current(),
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Error, Copy, Clone)]
pub enum PollerTimeoutError {
    #[error("Timeout")]
    Timeout,
}

impl Poller {
    pub fn poll(&mut self) -> ReadyTokensByBits<'_> {
        loop {
            if self.any_ready() {
                break;
            }
            std::thread::park();
        }

        self.iter_ready()
    }

    pub fn poll_timeout(
        &mut self,
        duration: Duration,
    ) -> Result<ReadyTokensByBits<'_>, PollerTimeoutError> {
        let deadline = Instant::now() + duration;

        loop {
            if deadline <= Instant::now() {
                return Err(PollerTimeoutError::Timeout);
            }
            if self.any_ready() {
                break;
            }
            std::thread::park_timeout(deadline.saturating_duration_since(Instant::now()));
        }

        Ok(self.iter_ready())
    }

    #[must_use]
    pub fn any_ready(&self) -> bool {
        self.ready_bits.iter().any(|x| {
            x.read.load(AtomicOrdering::Acquire) != 0 || x.write.load(AtomicOrdering::Acquire) != 0
        })
    }

    #[must_use]
    pub fn iter_ready(&self) -> ReadyTokensByBits<'_> {
        let mut ready_bits = vec![ReadyBitFrozen { read: 0, write: 0 }; self.ready_bits.len()];
        for i in 0..self.ready_bits.len() {
            ready_bits[i] = ReadyBitFrozen {
                read: self.ready_bits[i].read.swap(0, AtomicOrdering::Acquire),
                write: self.ready_bits[i].write.swap(0, AtomicOrdering::Acquire),
            };
        }

        ReadyTokensByBits::new(&self.targets[..], ready_bits)
    }

    pub fn register(
        &mut self,
        target: &mut (impl PollerReadRegister + PollerWriteRegister),
    ) -> std::io::Result<Rc<Token>> {
        let (chunk_index, bit_index, token, shared_state) = self.get_free_token();

        target.register_read(WakeHandle {
            thread: self.thread.clone(),
            bits: self.ready_bits[chunk_index].read.clone(),
            index: bit_index,
            shared_state: shared_state.clone(),
        })?;
        target.register_write(WakeHandle {
            thread: self.thread.clone(),
            bits: self.ready_bits[chunk_index].write.clone(),
            index: bit_index,
            shared_state,
        })?;

        Ok(token)
    }

    pub fn register_read(
        &mut self,
        target: &mut impl PollerReadRegister,
    ) -> std::io::Result<Rc<Token>> {
        let (chunk_index, bit_index, token, shared_state) = self.get_free_token();

        target.register_read(WakeHandle {
            thread: self.thread.clone(),
            bits: self.ready_bits[chunk_index].read.clone(),
            index: bit_index,
            shared_state,
        })?;

        Ok(token)
    }

    pub fn register_write(
        &mut self,
        target: &mut impl PollerWriteRegister,
    ) -> std::io::Result<Rc<Token>> {
        let (chunk_index, bit_index, token, shared_state) = self.get_free_token();

        target.register_write(WakeHandle {
            thread: self.thread.clone(),
            bits: self.ready_bits[chunk_index].write.clone(),
            index: bit_index,
            shared_state,
        })?;

        Ok(token)
    }
}

impl Poller {
    fn get_free_token(&mut self) -> (usize, u8, Rc<Token>, Arc<SharedState>) {
        let index = self
            .targets
            .iter()
            .position(|x| x.as_ref().and_then(|w| w.shared.upgrade()).is_none())
            .unwrap_or(self.targets.len());

        let chunk_index = index / u64::BITS as usize;
        #[allow(clippy::cast_possible_truncation)] // usize % 64 will not exced u8
        let chunk_bit_index: u8 = (index % u64::BITS as usize) as u8;

        if self.ready_bits.len() <= chunk_index {
            self.ready_bits
                .resize_with(chunk_index + 1, ReadyBitShared::default);
            self.targets
                .resize_with(self.ready_bits.len() * u64::BITS as usize, Default::default);
        }

        let shared_state = Arc::new(SharedState {
            dropped: AtomicBool::new(false),
        });

        let token = Rc::new(Token {
            id: index,
            shared_state: shared_state.clone(),
        });

        // We have already ensured there is enough space thanks to growing by u64::BYTES when we expaned ready_bits
        self.targets[index] = Some(TargetTracker {
            token: Rc::downgrade(&token),
            shared: Arc::downgrade(&shared_state),
        });

        (chunk_index, chunk_bit_index, token, shared_state)
    }
}

pub trait PollerReadRegister {
    fn register_read(&mut self, handle: WakeHandle) -> std::io::Result<()>;
}
pub trait PollerWriteRegister {
    fn register_write(&mut self, handle: WakeHandle) -> std::io::Result<()>;
}

#[derive(Debug, Copy, Clone)]
struct ReadyBitFrozen {
    read: u64,
    write: u64,
}
#[derive(Debug)]
pub struct ReadyTokensByBits<'a> {
    items: &'a [Option<TargetTracker>],
    ready_bits: Vec<ReadyBitFrozen>,
    current_chunk: usize,
}
impl<'a> ReadyTokensByBits<'a> {
    fn new(items: &'a [Option<TargetTracker>], ready_bits: Vec<ReadyBitFrozen>) -> Self {
        assert!(ready_bits.len() <= (items.len() * u64::BITS as usize));

        ReadyTokensByBits {
            items,
            ready_bits,
            current_chunk: 0,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ReadyState {
    Read,
    Write,
    Both,
}
impl ReadyState {
    #[must_use]
    pub const fn has_read(&self) -> bool {
        matches!(self, Self::Read) || matches!(self, Self::Both)
    }
    #[must_use]
    pub const fn has_write(&self) -> bool {
        matches!(self, Self::Write) || matches!(self, Self::Both)
    }
}

impl Iterator for ReadyTokensByBits<'_> {
    type Item = (Rc<Token>, ReadyState);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current_chunk >= self.ready_bits.len() {
                return None;
            }

            let chunk = self.ready_bits[self.current_chunk];
            if chunk.read == 0 && chunk.write == 0 {
                self.current_chunk += 1;
                continue;
            }

            // Count the number of trailing zeros to get the index of the next ready index
            // This lets us skip strait to that ready index
            let next_read = chunk.read.trailing_zeros() as usize;
            let next_write = chunk.write.trailing_zeros() as usize;

            // Work out if read or write has the next item - then only unset the appropriate indexes
            let (next, state) = match next_read.cmp(&next_write) {
                Ordering::Less => {
                    self.ready_bits[self.current_chunk].read &= chunk.read - 1;
                    (next_read, ReadyState::Read)
                }
                Ordering::Equal => {
                    self.ready_bits[self.current_chunk].read &= chunk.read - 1;
                    self.ready_bits[self.current_chunk].write &= chunk.write - 1;
                    (next_read, ReadyState::Both)
                }
                Ordering::Greater => {
                    self.ready_bits[self.current_chunk].write &= chunk.write - 1;
                    (next_write, ReadyState::Write)
                }
            };

            // We just need to reset that bit to zero now we are handling it
            // Convert the local bit index into an absolute index for our Tokens vec
            let absolute_index = next + (u64::BITS as usize * self.current_chunk);
            if absolute_index >= self.items.len() {
                return None;
            }

            if let Some(Some(item)) = self.items.get(absolute_index)
                && let Some(item) = item.token.upgrade()
            {
                return Some((item, state));
            }
        }
    }
}
