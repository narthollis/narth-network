use crate::protocols::arp::ArpMessage;
use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use crate::protocols::ipv4::icmp::ICMPMessage;
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header};
use crate::runtime::address_table::AddressTableIpv4;
use crate::runtime::channel::{NetworkSender, NetworkSenderError};
use crate::runtime::interface::l2_ethernet::ArpTable;
use crate::runtime::interface::{SendError, SendResult};
use crate::runtime::route_table::RouteTable;
use crate::write_to_buffer::WriteToBuffer;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use tracing::{error, trace};

#[derive(Debug)]
pub struct InterfaceContext {
    pub(super) mtu: usize,
    pub(super) mac_addr: MacAddr,

    pub(super) network_tx: NetworkSender,

    pub(super) arp_table: ArpTable,
    pub(super) ipv4_addresses: AddressTableIpv4,
    pub(super) ipv4_route_table: RouteTable<Ipv4Addr>,
    pub(super) ipv4_send_buffer: HashMap<Ipv4Addr, VecDeque<(IPv4Header, bytes::Bytes)>>,

    pub(super) ephemeral_ports: std::ops::Range<u16>,
}

impl InterfaceContext {
    pub fn send(&mut self, packet: &impl WriteToBuffer) -> SendResult {
        trace!("sending packet");

        let mut buffer = bytes::BytesMut::with_capacity(self.mtu);
        packet.write_to_buffer(&mut buffer);
        buffer.truncate(buffer.len());

        let buffer = buffer.freeze();

        if tracing::enabled!(tracing::Level::TRACE) {
            parse_and_log(&buffer);
        }

        match self
            .network_tx
            .try_send(super::super::channel::NetworkSendPayload::Packet(buffer))
        {
            Ok(_) => Ok(()),
            Err(NetworkSenderError::WakeError(err)) => {
                error!("Failed to wake network for new packet: {err:?}");
                // We queued the message, but just failed to wake the network
                Ok(())
            }
            Err(NetworkSenderError::SendError { .. }) => Err(SendError::BufferFull),
        }
    }
}

// TODO this doesn't really live here
fn parse_and_log(rem: &bytes::Bytes) {
    // this next part should be behind some kind of debug
    let e = match EthernetHeader::from_bytes(rem) {
        Ok(e) => e,
        Err(e) => {
            error!("failed to parse outgoing ethernet header: {}", e);
            return;
        }
    };
    trace!("Outgoing ethernet header: {:?}", e);

    let rem = &rem.slice(e.encoded_length()..);

    match e.ether_type() {
        EtherType::ARP => {
            let a = match ArpMessage::from_bytes(rem) {
                Ok(a) => a,
                Err(e) => {
                    error!("failed to parse outgoing arp message: {}", e);
                    return;
                }
            };
            trace!("Outgoing arp message: {:?}", a);
        }
        EtherType::IPv4 => {
            let ip = match IPv4Header::from_bytes(rem) {
                Ok(ip) => ip,
                Err(e) => {
                    error!("failed to parse outgoing l3_ipv4 header: {}", e);
                    return;
                }
            };
            trace!("Outgoing IPv4 header: {:?}", ip);
            let rem = &rem.slice(ip.encoded_length()..);
            match ip.protocol() {
                IPProtocolTypes::ICMP => {
                    let icmp = match ICMPMessage::from_bytes(rem) {
                        Ok(icmp) => icmp,
                        Err(e) => {
                            error!("failed to parse outgoing icmp message: {}", e);
                            return;
                        }
                    };
                    trace!("Outgoing ICMP message: {:?}", icmp);
                }
                IPProtocolTypes::UDP => {}
                _ => {}
            }
        }
        _ => {}
    }
}
