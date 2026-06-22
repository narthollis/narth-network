use crate::runtime::interface::l4_managers::udp::handle::UdpSocketHandle;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Copy, Clone)]
pub(super) enum AddressBindingTarget {
    Any,
    AnyIpv4,
    AnyIpv6,
    Specific(IpAddr),
}

#[derive(Debug)]
pub(super) struct AddressBinding {
    target: AddressBindingTarget,
    original: SocketAddr,
    handle: UdpSocketHandle,
}
impl AddressBinding {
    pub const fn is_any(&self) -> bool {
        match self.target {
            AddressBindingTarget::Any
            | AddressBindingTarget::AnyIpv4
            | AddressBindingTarget::AnyIpv6 => true,
            AddressBindingTarget::Specific(_) => false,
        }
    }

    pub const fn is_ipv4(&self) -> bool {
        match self.target {
            AddressBindingTarget::Any | AddressBindingTarget::AnyIpv4 => true,
            AddressBindingTarget::AnyIpv6 => false,
            AddressBindingTarget::Specific(ip) => ip.is_ipv4(),
        }
    }

    pub const fn is_only_ipv4(&self) -> bool {
        match self.target {
            AddressBindingTarget::Any | AddressBindingTarget::AnyIpv6 => false,
            AddressBindingTarget::AnyIpv4 => true,
            AddressBindingTarget::Specific(ip) => ip.is_ipv4(),
        }
    }

    pub const fn is_ipv6(&self) -> bool {
        match self.target {
            AddressBindingTarget::Any | AddressBindingTarget::AnyIpv6 => true,
            AddressBindingTarget::AnyIpv4 => false,
            AddressBindingTarget::Specific(ip) => ip.is_ipv6(),
        }
    }

    pub const fn is_only_ipv6(&self) -> bool {
        match self.target {
            AddressBindingTarget::Any | AddressBindingTarget::AnyIpv4 => false,
            AddressBindingTarget::AnyIpv6 => true,
            AddressBindingTarget::Specific(ip) => ip.is_ipv6(),
        }
    }

    pub fn matches(&self, ip: &IpAddr) -> bool {
        // This is much cleaner if we don't merge the arms
        #[allow(clippy::match_same_arms)]
        match (self.target, ip.is_ipv4()) {
            (AddressBindingTarget::Any, _) => true,
            (AddressBindingTarget::AnyIpv4, true) => true,
            (AddressBindingTarget::AnyIpv4, false) => false,
            (AddressBindingTarget::AnyIpv6, true) => false,
            (AddressBindingTarget::AnyIpv6, false) => true,
            (AddressBindingTarget::Specific(l), _) => ip == &l,
        }
    }

    pub const fn allows_reuse(&self) -> bool {
        self.handle.allow_reuse
    }
}

#[derive(Debug)]
pub(super) struct AddressBindings(
    /// None address is an unspecified binding for both IPv4 and IPv5
    /// This is done because UdpSocketHandle can't be cloneable due to ringbuf handles
    Vec<AddressBinding>,
);

impl AddressBindings {
    fn is_bindable_exclusive(
        &self,
        request: &SocketAddr,
        unspecified_binds_dual_stack: bool,
    ) -> bool {
        // When trying to bind exclusively to any address we can fast track some checks
        if request.ip().is_unspecified() {
            // If we are trying to bind dual stack (which should be our default)
            if unspecified_binds_dual_stack {
                // All we need to do when binding exclusively is check there are no other bindings
                self.0.is_empty()
            } else {
                // Otherwise we need to check there are no bindings for the matching IP version
                if request.is_ipv4() {
                    !self.0.iter().any(|a| a.is_ipv4())
                } else {
                    !self.0.iter().any(|a| a.is_ipv6())
                }
            }
        } else {
            for binding in &self.0 {
                if binding.matches(&request.ip()) {
                    return false;
                }
            }

            true
        }
    }

    fn is_bindable_allow_reuse(
        &self,
        request: &SocketAddr,
        unspecified_binds_dual_stack: bool,
    ) -> bool {
        if request.ip().is_unspecified() {
            if unspecified_binds_dual_stack {
                self.0.iter().all(AddressBinding::allows_reuse)
            } else if request.is_ipv4() {
                self.0
                    .iter()
                    .filter(|a| a.is_ipv4())
                    .all(AddressBinding::allows_reuse)
            } else {
                self.0
                    .iter()
                    .filter(|a| a.is_ipv6())
                    .all(AddressBinding::allows_reuse)
            }
        } else {
            !self
                .0
                .iter()
                .filter(|a| a.matches(&request.ip()))
                .any(|a| !a.allows_reuse())
        }
    }

    pub fn is_bindable(
        &self,
        request: &SocketAddr,
        allow_reuse: bool,
        unspecified_binds_dual_stack: bool,
    ) -> bool {
        if allow_reuse {
            self.is_bindable_allow_reuse(request, unspecified_binds_dual_stack)
        } else {
            self.is_bindable_exclusive(request, unspecified_binds_dual_stack)
        }
    }

    pub fn get_mut(&mut self, request: &IpAddr) -> Option<&mut UdpSocketHandle> {
        if let Some(binding) = self.0.iter_mut().find(|binding| binding.matches(request)) {
            Some(&mut binding.handle)
        } else {
            None
        }
    }

    pub fn insert(
        &mut self,
        addr: SocketAddr,
        handle: UdpSocketHandle,
        unspecified_binds_dual_stack: bool,
    ) {
        let binding = if addr.ip().is_unspecified() {
            if unspecified_binds_dual_stack {
                AddressBinding {
                    target: AddressBindingTarget::Any,
                    original: addr,
                    handle,
                }
            } else if addr.is_ipv4() {
                AddressBinding {
                    target: AddressBindingTarget::AnyIpv4,
                    original: addr,
                    handle,
                }
            } else {
                AddressBinding {
                    target: AddressBindingTarget::AnyIpv6,
                    original: addr,
                    handle,
                }
            }
        } else {
            AddressBinding {
                target: AddressBindingTarget::Specific(addr.ip()),
                original: addr,
                handle,
            }
        };
        self.0.push(binding);
    }

    pub fn remove(&mut self, addr: &SocketAddr) {
        if let Some(position) = self.0.iter().position(|x| x.original == *addr) {
            self.0.remove(position);
        }
    }
}

#[derive(Debug)]
// Plus 1 because 65_335 is a valid port, and this is easer/cleaner than remember to -1 all the time
pub(super) struct PortBindings([Option<Box<AddressBindings>>; u16::MAX as usize + 1]);

impl Default for PortBindings {
    fn default() -> Self {
        PortBindings([const { None }; u16::MAX as usize + 1])
    }
}

impl PortBindings {
    pub fn is_bindable(
        &self,
        addr: &SocketAddr,
        allow_reuse: bool,
        unspecified_binds_dual_stack: bool,
    ) -> bool {
        self.0[addr.port() as usize]
            .as_ref()
            .is_none_or(|port| port.is_bindable(addr, allow_reuse, unspecified_binds_dual_stack))
    }

    pub fn insert(
        &mut self,
        addr: SocketAddr,
        handle: UdpSocketHandle,
        unspecified_binds_dual_stack: bool,
    ) {
        if self.0[addr.port() as usize].is_none() {
            self.0[addr.port() as usize] = Some(Box::new(AddressBindings(Vec::new())));
        }

        self.0[addr.port() as usize]
            .as_mut()
            .expect("unreachable")
            .insert(addr, handle, unspecified_binds_dual_stack);
    }

    pub fn get_mut(&mut self, input: &SocketAddr) -> Option<&mut UdpSocketHandle> {
        self.0[input.port() as usize]
            .as_mut()
            .and_then(|port| port.get_mut(&input.ip()))
    }

    pub fn remove(&mut self, original: &SocketAddr) {
        if let Some(port) = self.0[original.port() as usize].as_mut() {
            port.remove(original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::interface::l4_managers::udp::UdpSocketSharedState;
    use crate::runtime::interface::l4_managers::udp::messages::SharableUdpSendResult;
    use ringbuf::traits::Split;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, RwLock};

    // Helper to spin up a mock handle with the designated reuse flag
    fn make_handle(allow_reuse: bool) -> UdpSocketHandle {
        let (recv_tx, _) = ringbuf::HeapRb::new(1).split();
        let (_, send_rx) = ringbuf::HeapRb::new(1).split();
        UdpSocketHandle {
            recv_tx,
            send_rx,
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            peer_addr: None,
            shared_state: Arc::new(UdpSocketSharedState {
                send_result: SharableUdpSendResult::default(),
                connected_to: RwLock::default(),
                is_nonblocking: AtomicBool::default(),
                allow_broadcast: AtomicBool::default(),
                max_payload_size: 1500.into(),
            }),
            read_wake_handle: None,
            write_wake_handle: None,
            allow_reuse,
        }
    }

    // Helper to generate a SocketAddr quickly
    fn make_addr(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    #[test]
    fn test_port_bindings_array_boundary() {
        let bindings = PortBindings::default();
        let max_port_addr = make_addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 65535);

        // This would panic if the array size was exactly u16::MAX
        let result = bindings.is_bindable(&max_port_addr, false, true);
        assert!(
            result,
            "Port 65535 should be safely indexable without panic"
        );
    }

    #[test]
    fn test_exclusive_unspecified_dual_stack() {
        let mut bindings = AddressBindings(Vec::new());
        let req_v4 = make_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80);
        let req_v6 = make_addr(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80);

        // 1. Empty bindings should allow exclusive dual-stack wildcard bind
        assert!(bindings.is_bindable(&req_v4, false, true));

        // Simulate a dual-stack Any bind being added
        bindings.0.push(AddressBinding {
            target: AddressBindingTarget::Any,
            original: make_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80),
            handle: make_handle(false),
        });

        // 2. Once Any is occupied exclusively, subsequent wildcard binds must fail
        assert!(!bindings.is_bindable(&req_v4, false, true));
        assert!(!bindings.is_bindable(&req_v6, false, true));
    }

    #[test]
    fn test_exclusive_unspecified_single_stack() {
        let mut bindings = AddressBindings(Vec::new());
        let req_v4 = make_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80);
        let req_v6 = make_addr(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80);

        // Simulate an exclusive IPv4-only wildcard bind
        bindings.0.push(AddressBinding {
            target: AddressBindingTarget::AnyIpv4,
            original: make_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80),
            handle: make_handle(false),
        });

        // An incoming exclusive IPv4 wildcard bind should be rejected
        assert!(!bindings.is_bindable(&req_v4, false, false));

        // An incoming exclusive IPv6 wildcard bind should be ALLOWED because realms don't cross
        assert!(bindings.is_bindable(&req_v6, false, false));
    }

    #[test]
    fn test_exclusive_specific_ip_conflict() {
        let mut bindings = AddressBindings(Vec::new());
        let local_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 12));
        let other_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 13));
        let req_addr = make_addr(local_v4, 80);
        let req_other = make_addr(other_v4, 80);

        // Simulate an exclusive binding to a specific IPv4 address
        bindings.0.push(AddressBinding {
            target: AddressBindingTarget::Specific(local_v4),
            original: make_addr(local_v4, 80),
            handle: make_handle(false),
        });

        // 1. Exact same IP should fail
        assert!(!bindings.is_bindable(&req_addr, false, false));

        // 2. Different IP on the same port should pass
        assert!(bindings.is_bindable(&req_other, false, false));

        // 3. Trying to bind a wildcard when a specific IP is exclusive should fail
        let wildcard_v4 = make_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80);
        assert!(!bindings.is_bindable(&wildcard_v4, false, false));
    }

    #[test]
    fn test_allow_reuse_mutual_agreement() {
        let mut bindings = AddressBindings(Vec::new());
        let local_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 12));
        let req_addr = make_addr(local_v4, 80);

        // Scenario 1: Existing socket does NOT allow reuse, new one DOES -> Should FAIL
        bindings.0.push(AddressBinding {
            target: AddressBindingTarget::Specific(local_v4),
            original: make_addr(local_v4, 80),
            handle: make_handle(false),
        });
        assert!(!bindings.is_bindable(&req_addr, true, false));

        // Scenario 2: Existing socket DOES allow reuse, new one does NOT -> Should FAIL
        bindings.0.clear();
        bindings.0.push(AddressBinding {
            target: AddressBindingTarget::Specific(local_v4),
            original: make_addr(local_v4, 80),
            handle: make_handle(true),
        });
        assert!(!bindings.is_bindable(&req_addr, false, false));

        // Scenario 3: Both sockets allow reuse -> Should SUCCESS
        assert!(bindings.is_bindable(&req_addr, true, false));
    }

    #[test]
    fn test_allow_reuse_overlapping_wildcards() {
        let mut bindings = AddressBindings(Vec::new());
        let wildcard_v4 = make_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80);

        // Pre-populate with a reusable AnyIpv4 binding
        bindings.0.push(AddressBinding {
            target: AddressBindingTarget::AnyIpv4,
            original: make_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80),
            handle: make_handle(true),
        });

        // Requesting another AnyIpv4 with reuse allowed should succeed
        assert!(bindings.is_bindable(&wildcard_v4, true, false));

        // Requesting a dual-stack Any wildcard with reuse allowed should also succeed
        assert!(bindings.is_bindable(&wildcard_v4, true, true));
    }

    #[test]
    fn test_ipv6_specific_classification_fixed() {
        let local_v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xdead, 0xbeef, 0, 1));
        let binding = AddressBinding {
            target: AddressBindingTarget::Specific(local_v6),
            original: make_addr(local_v6, 80),
            handle: make_handle(false),
        };

        // Verifies the fix for the typo bug in the is_ipv6 helper method
        assert!(
            binding.is_ipv6(),
            "Specific IPv6 bindings must return true for is_ipv6"
        );
        assert!(
            !binding.is_ipv4(),
            "Specific IPv6 bindings must return false for is_ipv4"
        );
    }
}
