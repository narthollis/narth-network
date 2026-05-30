use crate::protocols::ethernet::mac::MacAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

mod address_table;
pub(in crate::runtime) mod common;
pub mod interface;
pub mod network;
mod ping;
mod route_table;

pub trait NetworkBridge {
    type Error: core::fmt::Debug;

    fn mtu(&self) -> usize;
    fn mac_addr(&self) -> MacAddr;

    /// IPv4 Addresses associated with the interface this represents
    /// If this represents a raw Ethernet device or a pure bridge this should return nothing
    fn ipv4_addresses(&self) -> Result<impl IntoIterator<Item = Ipv4Addr>, Self::Error>;
    /// IPv6 Addresses associated with the interface this represents
    /// If this represents a raw Ethernet device or a pure bridge this should return nothing
    fn ipv6_addresses(&self) -> Result<impl IntoIterator<Item = Ipv6Addr>, Self::Error>;

    fn send(&mut self, packet: &[u8]) -> std::io::Result<usize>;
    fn recv(&mut self, buffer: &mut [u8]) -> std::io::Result<usize>;
}
