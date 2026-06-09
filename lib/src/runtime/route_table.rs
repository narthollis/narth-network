use std::cmp::Ordering;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::BitAnd;
use std::sync::{Arc, RwLock};

#[derive(Debug, Eq, Clone, Copy)]
pub struct RouteInformation<T: Ord> {
    pub target: T,
    pub mask: T,

    pub source: T,
    pub next_hop: Option<T>,
}

impl<T: Ord> PartialEq<Self> for RouteInformation<T> {
    fn eq(&self, other: &Self) -> bool {
        self.target == other.target && self.mask == other.mask
    }
}

impl<T: Ord> Ord for RouteInformation<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Intentionally invert the comparison so we end up with longest first
        other
            .mask
            .cmp(&self.mask)
            .then_with(|| self.target.cmp(&other.target))
    }
}

impl<T: Ord> PartialOrd<Self> for RouteInformation<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
pub struct RouteTable<T: Ord + BitAnd<Output = T>> {
    routes: Vec<RouteInformation<T>>,
    shared: Arc<RwLock<Vec<RouteInformation<T>>>>,
}

impl<T: Ord + BitAnd<Output = T> + Clone + Copy> RouteTable<T> {
    pub fn shared(&self) -> Arc<RwLock<Vec<RouteInformation<T>>>> {
        self.shared.clone()
    }

    fn update_shared(&self) {
        let next = self.routes.clone();
        let mut shared = self.shared.write().expect("route table poisoned rwlock");
        *shared = next;
    }

    pub fn insert_or_update(&mut self, target: T, mask: T, source: T, next_hop: Option<T>) {
        let new = RouteInformation {
            target,
            mask,
            source,
            next_hop,
        };

        match self.routes.binary_search(&new) {
            // Ok is when binary found something
            Ok(index) => self.routes[index] = new,
            // Err it didn't but instead tells us where it should be
            Err(index) => self.routes.insert(index, new),
        }

        self.update_shared();
    }

    pub fn remove_matching(&mut self, predicate: impl Fn(&&RouteInformation<T>) -> bool) {
        self.routes.retain(|route| !predicate(&route));
        self.update_shared();
    }

    pub fn lookup(&self, target: &T) -> Option<&RouteInformation<T>> {
        self.routes.iter().find(|r| (*target & r.mask) == r.target)
    }
}

impl Default for RouteTable<Ipv4Addr> {
    fn default() -> Self {
        Self {
            routes: Vec::default(),
            shared: Arc::default(),
        }
    }
}

impl Default for RouteTable<Ipv6Addr> {
    fn default() -> Self {
        Self {
            routes: Vec::default(),
            shared: Arc::default(),
        }
    }
}
