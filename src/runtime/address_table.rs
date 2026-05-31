use std::collections::HashMap;
use std::hash::Hash;
use std::ops::BitAnd;
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct AddressTable<T: Eq + Hash + Clone + Copy> {
    local: HashMap<T, T>,
    shared: Arc<RwLock<Vec<(T, T)>>>,
}

impl<T: Eq + Hash + Clone + Copy> Default for AddressTable<T> {
    fn default() -> Self {
        AddressTable {
            shared: Default::default(),
            local: Default::default(),
        }
    }
}

impl<T: Eq + Hash + Clone + Copy + BitAnd<Output = T>> AddressTable<T> {
    pub fn shared(&self) -> Arc<RwLock<Vec<(T, T)>>> {
        self.shared.clone()
    }

    fn update(&self) {
        let next = self.local.iter().map(|(a, m)| (*a, *m)).collect();
        let mut shared = self.shared.write().expect("shared lock poisoned");
        *shared = next;
    }

    pub fn insert(&mut self, value: T, mask: T) {
        self.local.insert(value, mask);
        self.update();
    }

    pub fn remove(&mut self, value: &T) {
        self.local.remove(value);
        self.update();
    }

    pub fn contains(&self, value: &T) -> bool {
        self.local.contains_key(value)
    }

    /// Find the first assigned address whose subnet contains value
    pub fn first_with_subnet_containing(&self, value: &T) -> Option<T> {
        self.local
            .iter()
            .find(|(addr, mask)| *value & **mask == **addr & **mask)
            .map(|(addr, _)| *addr)
    }
}
