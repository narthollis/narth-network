use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

#[derive(Debug)]
struct InterfaceIpv4Addr {
    address: Ipv4Addr,
    mask: Ipv4Addr,
    broadcast: Ipv4Addr,
    network: Ipv4Addr,
}

impl InterfaceIpv4Addr {
    fn new(address: Ipv4Addr, mask: Ipv4Addr) -> Self {
        let network = address & mask;

        Self {
            address,
            mask,
            network,
            broadcast: network | !mask,
        }
    }
}

#[derive(Debug, Default)]
pub struct AddressTableIpv4 {
    /// Non-blocking local data copy for 'kernel' side address lookups
    local: Vec<InterfaceIpv4Addr>,
    /// Shared address list shared with the 'userspace' side of things
    shared: Arc<RwLock<Vec<(Ipv4Addr, Ipv4Addr)>>>,
}

impl AddressTableIpv4 {
    pub fn shared(&self) -> Arc<RwLock<Vec<(Ipv4Addr, Ipv4Addr)>>> {
        self.shared.clone()
    }

    fn update(&self) {
        let next = self.local.iter().map(|a| (a.address, a.mask)).collect();
        let mut shared = self.shared.write().expect("shared lock poisoned");
        *shared = next;
    }

    pub fn insert(&mut self, addr: Ipv4Addr, mask: Ipv4Addr) {
        self.local.push(InterfaceIpv4Addr::new(addr, mask));
        self.update();
    }

    pub fn remove(&mut self, value: Ipv4Addr) {
        if let Some(position) = self.local.iter().position(|a| a.address == value) {
            self.local.remove(position);
        }
        self.update();
    }

    pub fn contains(&self, value: Ipv4Addr) -> bool {
        self.local.iter().any(|a| a.address == value)
    }
    pub fn contains_as_address_or_broadcast(&self, value: Ipv4Addr) -> bool {
        self.local
            .iter()
            .any(|a| a.address == value || a.broadcast == value)
    }

    pub fn contains_ephemeral_multicast(&self, value: Ipv4Addr) -> bool {
        // TODO implement me
        false
    }

    /// Find the first assigned address whose subnet contains value
    pub fn first_with_subnet_containing(&self, value: Ipv4Addr) -> Option<Ipv4Addr> {
        self.local
            .iter()
            .find(|a| value & a.mask == a.network)
            .map(|a| a.address)
    }
}
