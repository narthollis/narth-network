use crate::common::WriteToBuffer;
use crate::protocols::arp::{ArpMessage, ArpState, ArpTable};
use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use crate::protocols::ipv4::icmp::ICMPMessage;
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header};
use crate::runtime::common::{NetworkSender, NetworkSenderError};
use crate::runtime::interface::interface_worker::InterfaceWorker;
use crate::runtime::interface::{SendError, SendResult};
use crate::runtime::route_table::RouteTable;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use tracing::{error, trace};

#[derive(Debug)]
pub(crate) struct SenderContext {
    pub(super) mtu: usize,
    pub(super) mac_addr: MacAddr,
    pub(super) network_tx: NetworkSender,
    pub(super) arp_table: ArpTable,
    pub(super) ipv4_route_table: RouteTable<Ipv4Addr>,
    pub(super) ipv4_send_buffer: HashMap<Ipv4Addr, VecDeque<(IPv4Header, bytes::Bytes)>>,
}

impl SenderContext {
    fn send(&mut self, packet: &impl WriteToBuffer) -> SendResult {
        trace!("sending packet");

        assert!(packet.encoded_length() <= self.mtu);

        let mut buffer = bytes::BytesMut::with_capacity(self.mtu);
        packet.write_to_buffer(&mut buffer);
        buffer.truncate(buffer.len());

        let buffer = buffer.freeze();

        if tracing::enabled!(tracing::Level::TRACE) {
            parse_and_log(&buffer);
        }

        match self
            .network_tx
            .try_send(super::super::common::NetworkSendPayload::Packet(buffer))
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

    pub fn send_ethernet(
        &mut self,
        destination: MacAddr,
        ether_type: EtherType,
        payload: &impl WriteToBuffer,
    ) -> SendResult {
        let header = EthernetHeader::new(ether_type, self.mac_addr, destination);

        // Ethernet frames are caped at MTU - this should already be handled by Layer4, so I'm keeping the 'assert!' here
        assert!(header.encoded_length() + payload.encoded_length() <= self.mtu);

        self.send(&(header, payload))
    }

    pub fn send_ipv4(
        &mut self,
        destination: Ipv4Addr,
        source: Ipv4Addr,
        protocol: IPProtocolTypes,
        payload: &impl WriteToBuffer,
    ) -> SendResult {
        // ICMP requires the first 64 bits/8 bytes of the payload be included in control messages - so an IP frame
        // less than that should be considered mal-formed
        if payload.encoded_length() < 8 {
            return Err(SendError::PayloadTooShort);
        }
        // This is where we should do fragmentation if were supported it
        // I'm not going to support that, so sync-reject
        // TODO This is where we would handle the Path MTU lookup
        if (payload.encoded_length() + IPv4Header::MIN_LENGTH) > self.mtu {
            return Err(SendError::PayloadTooLarge {
                max_size: self.mtu - IPv4Header::MIN_LENGTH,
            });
        }

        let payload = {
            let mut buff = bytes::BytesMut::with_capacity(payload.encoded_length());
            payload.write_to_buffer(&mut buff);
            buff.freeze()
        };
        let payload_len: u16 = payload.len().try_into().expect("payload length overflow");

        let Some(route) = self.ipv4_route_table.lookup(destination) else {
            return Err(SendError::NoRouteToHost);
        };
        let source = source.or_unspecified(route.source);

        let header = IPv4Header::new(protocol, source, destination, payload_len);

        let next_hop = route.next_hop.unwrap_or(destination);

        let arp_state = self.arp_table.request(next_hop, source);
        trace!("arp table said {:?} for {}", arp_state, next_hop);

        // Check if we need to send an ARP request
        match arp_state {
            ArpState::PendingRetry { source } => self.send_arp_request(next_hop, source)?,
            ArpState::ResolvedStale(_) | ArpState::Restart => {
                self.send_arp_request(next_hop, source)?;
            }
            _ => {}
        }

        match arp_state {
            ArpState::PendingRetry { .. } | ArpState::PendingWait { .. } | ArpState::Restart => {
                trace!("so we buffer the message");
                let buff = self.ipv4_send_buffer.entry(next_hop).or_default();
                if buff.len() < InterfaceWorker::MAX_IPV4_PENDING_BUFFER_SIZE {
                    buff.push_back((header, payload));
                } else {
                    return Err(SendError::ArpResolveBufferFull);
                }
            }
            ArpState::Resolved(dest_mac) | ArpState::ResolvedStale(dest_mac) => {
                trace!("so we send the message");
                self.send_ethernet(dest_mac, EtherType::IPv4, &(header, payload))?;
            }
            ArpState::Timeout => {
                trace!("so we return arp timeout");
                return Err(SendError::ArpTimeout);
            }
        };

        Ok(())
    }

    pub fn send_gratuitous_arp(&mut self, ipv4addr: Ipv4Addr) -> SendResult {
        let arp = ArpMessage::gratuitous(self.mac_addr, ipv4addr);
        self.send_ethernet(arp.target_mac(), EtherType::ARP, &arp)
    }

    pub fn send_arp_request(&mut self, target_ipv4: Ipv4Addr, source_ipv4: Ipv4Addr) -> SendResult {
        // TODO maybe push this down into the ARP manger?
        if self.arp_table.can_send_request(target_ipv4, source_ipv4) {
            let arp = ArpMessage::request(self.mac_addr, target_ipv4, source_ipv4);

            self.send_ethernet(arp.target_mac(), EtherType::ARP, &arp)?;
        }

        Ok(())
    }
}

trait OrUnspecified {
    fn or_unspecified(self, other: Self) -> Self;
}
impl OrUnspecified for Ipv4Addr {
    fn or_unspecified(self, other: Self) -> Self {
        if self.is_unspecified() {
            return other;
        }
        self
    }
}

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
                    error!("failed to parse outgoing ipv4 header: {}", e);
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
