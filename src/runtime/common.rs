use crate::protocols::ethernet::EthernetHeader;
use crate::protocols::ethernet::mac::MacAddr;
use std::collections::HashSet;
use std::hash::Hash;
use std::io;
use std::sync::{Arc, RwLock, mpsc, oneshot};

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

#[derive(Debug)]
pub struct HashSetSharedRead<T: Eq + Hash + Clone> {
    local: HashSet<T>,
    shared: Arc<RwLock<Vec<T>>>,
}

impl<T: Eq + Hash + Clone> Default for HashSetSharedRead<T> {
    fn default() -> Self {
        HashSetSharedRead {
            shared: Default::default(),
            local: Default::default(),
        }
    }
}

impl<T: Eq + Hash + Clone> HashSetSharedRead<T> {
    pub fn shared(&self) -> Arc<RwLock<Vec<T>>> {
        self.shared.clone()
    }

    fn update(&self) {
        let next = self.local.iter().cloned().collect();
        let mut shared = self.shared.write().expect("shared lock poisoned");
        *shared = next;
    }

    pub fn insert(&mut self, value: T) {
        self.local.insert(value);
        self.update();
    }

    pub fn remove(&mut self, value: &T) {
        self.local.remove(value);
        self.update();
    }

    pub fn contains(&self, value: &T) -> bool {
        self.local.contains(value)
    }
}
