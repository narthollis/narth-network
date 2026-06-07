use crate::protocols::ethernet::mac::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::time::Instant;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ArpState {
    /// ARP Request is pending but above timeout, send a new request and let us know
    /// this is also the initial resolve state if no existing entry is found
    PendingRetry {
        source: Ipv4Addr,
    },
    Restart,
    /// ARP Request is pending but below timeout, hold your horses
    PendingWait {
        deadline: Instant,
    },
    /// If Pending wait time exced and max retry exced
    Timeout,
    /// The entry exists and is current - enjoy
    Resolved(MacAddr),
    /// The entry exists, but it's outside the TTL - so use this but also send a new request please
    ResolvedStale(MacAddr),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ArpTableEntry {
    Pending {
        since: Instant,
        retry_count: u8,
        source: Ipv4Addr,
    },
    Resolved {
        last_seen: Instant,
        address: MacAddr,
    },
    // Shares a TTL with Resolved
    Timeout {
        since: Instant,
    },
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct ArpTable {
    table: HashMap<Ipv4Addr, ArpTableEntry>,
}

const ARP_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
const ARP_REQUEST_MAX_RETRY: u8 = 5;
const ARP_LIFETIME_SEC: u64 = 30;
const ARP_LIFETIME: std::time::Duration = std::time::Duration::from_secs(ARP_LIFETIME_SEC);
const ARP_LIFETIME_STALE_SEC: u64 = 60;

impl ArpTable {
    pub fn update_or_insert(&mut self, mac: MacAddr, ipv4: Ipv4Addr) -> bool {
        self.table
            .insert(
                ipv4,
                ArpTableEntry::Resolved {
                    last_seen: Instant::now(),
                    address: mac,
                },
            )
            .is_some()
    }

    pub fn update_only(&mut self, mac: MacAddr, ipv4: Ipv4Addr) -> bool {
        match self.table.entry(ipv4) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(ArpTableEntry::Resolved {
                    last_seen: Instant::now(),
                    address: mac,
                });
                true
            }
            std::collections::hash_map::Entry::Vacant(_) => false,
        }
    }

    pub fn request(&mut self, target: Ipv4Addr, source: Ipv4Addr) -> ArpState {
        match self.table.entry(target) {
            std::collections::hash_map::Entry::Occupied(mut entry) => match entry.get() {
                ArpTableEntry::Pending {
                    retry_count,
                    since,
                    source,
                } => {
                    if since.elapsed() > ARP_REQUEST_TIMEOUT {
                        if *retry_count >= ARP_REQUEST_MAX_RETRY {
                            entry.insert(ArpTableEntry::Timeout {
                                since: Instant::now(),
                            });

                            ArpState::Timeout
                        } else {
                            ArpState::PendingRetry { source: *source }
                        }
                    } else {
                        ArpState::PendingWait {
                            deadline: since.add(ARP_REQUEST_TIMEOUT),
                        }
                    }
                }
                ArpTableEntry::Timeout { since } => {
                    if since.elapsed() > ARP_LIFETIME {
                        entry.remove();
                        ArpState::Restart
                    } else {
                        ArpState::Timeout
                    }
                }
                ArpTableEntry::Resolved { last_seen, address } => match last_seen
                    .elapsed()
                    .as_secs()
                {
                    ARP_LIFETIME_STALE_SEC.. => {
                        entry.remove();
                        ArpState::Restart
                    }
                    ARP_LIFETIME_SEC..ARP_LIFETIME_STALE_SEC => ArpState::ResolvedStale(*address),
                    ..ARP_LIFETIME_SEC => ArpState::Resolved(*address),
                },
            },
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(ArpTableEntry::Pending {
                    since: Instant::now(),
                    retry_count: 0,
                    source,
                });
                ArpState::PendingRetry { source }
            }
        }
    }

    #[must_use]
    pub fn pending(&self) -> Vec<(Ipv4Addr, Ipv4Addr)> {
        self.table
            .iter()
            .filter_map(|(ip, entry)| {
                if let ArpTableEntry::Pending { source, .. } = entry {
                    Some((*ip, *source))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn can_send_request(&mut self, target: Ipv4Addr, source: Ipv4Addr) -> bool {
        let now = Instant::now();
        let entry = self
            .table
            .entry(target)
            .and_modify(|mut entry| {
                if let ArpTableEntry::Pending {
                    retry_count, since, ..
                } = &mut entry
                {
                    *retry_count += 1;
                    *since = now;
                }
            })
            .or_insert(ArpTableEntry::Pending {
                since: now,
                retry_count: 0,
                source,
            });
        matches!(entry, ArpTableEntry::Pending { .. })
    }
}
