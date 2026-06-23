mod arp_table;

use crate::protocols::arp::{ArpMessage, Operation};
use crate::protocols::ethernet::mac::MacAddr;
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use crate::protocols::ipv4::IPv4Header;
use crate::protocols::ipv4::icmp::ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH;
use crate::runtime::interface::AsyncSendError::LocalSendError;
use crate::runtime::interface::SendError::ArpTimeout;
use crate::runtime::interface::l3_ipv4::IPv4Handler;
use crate::runtime::interface::l4_managers::Managers;
use crate::runtime::interface::{
    AsyncSendError, InterfaceContext, InterfaceWorker, SendError, SendResult,
};
use crate::write_to_buffer::WriteToBuffer;
pub use arp_table::{ArpState, ArpTable};
use std::net::Ipv4Addr;
use tracing::{debug, error, trace, trace_span};

pub struct EthernetHandler {}

impl EthernetHandler {
    pub fn send(
        ctx: &mut InterfaceContext,
        destination: MacAddr,
        ether_type: EtherType,
        payload: &impl WriteToBuffer,
    ) -> SendResult {
        let header = EthernetHeader::new(ether_type, ctx.mac_addr, destination);

        // Ethernet frames are caped at MTU - this should already be handled by Layer4, so I'm keeping the 'assert!' here
        assert!(header.encoded_length() + payload.encoded_length() <= ctx.mtu);

        ctx.send(&(header, payload))
    }

    pub fn send_ipv4(
        ctx: &mut InterfaceContext,
        next_hop: Ipv4Addr,
        source: Ipv4Addr,
        header: IPv4Header,
        payload: impl WriteToBuffer,
    ) -> SendResult {
        let arp_state = ctx.arp_table.request(next_hop, source);
        trace!("arp table said {:?} for {}", arp_state, next_hop);

        // Check if we need to send an ARP request
        match arp_state {
            ArpState::PendingRetry { source } => Self::send_arp_request(ctx, next_hop, source)?,
            ArpState::ResolvedStale(_) | ArpState::Restart => {
                Self::send_arp_request(ctx, next_hop, source)?;
            }
            _ => {}
        }

        match arp_state {
            ArpState::PendingRetry { .. } | ArpState::PendingWait { .. } | ArpState::Restart => {
                trace!("so we buffer the message");
                let buff = ctx.ipv4_send_buffer.entry(next_hop).or_default();
                if buff.len() < InterfaceWorker::MAX_IPV4_PENDING_BUFFER_SIZE {
                    let payload = {
                        let mut buff = bytes::BytesMut::with_capacity(payload.encoded_length());
                        payload.write_to_buffer(&mut buff);
                        buff.freeze()
                    };
                    buff.push_back((header, payload));
                    Ok(())
                } else {
                    Err(SendError::ArpResolveBufferFull)
                }
            }
            ArpState::Resolved(dest_mac) | ArpState::ResolvedStale(dest_mac) => {
                trace!("so we send the message");
                Self::send(ctx, dest_mac, EtherType::IPv4, &(header, payload))
            }
            ArpState::Timeout => {
                trace!("so we return arp timeout");
                Err(SendError::ArpTimeout)
            }
        }
    }

    pub fn send_arp_request(
        ctx: &mut InterfaceContext,
        target_ipv4: Ipv4Addr,
        source_ipv4: Ipv4Addr,
    ) -> SendResult {
        // TODO maybe push this down into the ARP manger?
        if ctx.arp_table.can_send_request(target_ipv4, source_ipv4) {
            let arp = ArpMessage::request(ctx.mac_addr, target_ipv4, source_ipv4);

            Self::send(ctx, arp.target_mac(), EtherType::ARP, &arp)
        } else {
            Ok(())
        }
    }

    pub fn send_gratuitous_arp(ctx: &mut InterfaceContext, ipv4addr: Ipv4Addr) -> SendResult {
        let arp = ArpMessage::gratuitous(ctx.mac_addr, ipv4addr);
        Self::send(ctx, arp.target_mac(), EtherType::ARP, &arp)
    }

    pub fn recv(ctx: &mut InterfaceContext, managers: &mut Managers, bytes: bytes::Bytes) {
        let ethernet_header = match EthernetHeader::from_bytes(&bytes) {
            Ok(ethernet_header) => ethernet_header,
            Err(e) => {
                debug!("failed to parse ethernet header: {}", e);
                return;
            }
        };
        let ethernet_payload = bytes.slice(ethernet_header.encoded_length()..);

        trace_span!(
            "recv",
            ethernet_source = ethernet_header.source_address().to_string(),
            ethernet_destination = ethernet_header.destination_address().to_string(),
        );
        trace!("Incoming Ethernet header: {:?}", ethernet_header);

        match ethernet_header.ether_type() {
            EtherType::ARP => Self::recv_arp(ctx, managers, ethernet_payload),
            EtherType::IPv4 => IPv4Handler::recv(ctx, managers, &ethernet_payload),
            EtherType::IPv6 => {
                // TODO
            }
            t => debug!("unsupported ethernet type: {:?}", t),
        }
    }

    pub fn recv_arp(ctx: &mut InterfaceContext, managers: &mut Managers, bytes: bytes::Bytes) {
        let arp = match ArpMessage::from_bytes(&bytes) {
            Ok(arp) => arp,
            Err(e) => {
                debug!("failed to parse arp message: {}", e);
                return;
            }
        };
        trace!("Incoming ARP: {:?}", arp);

        // https://datatracker.ietf.org/doc/rfc826/ Packet Reception

        // Update the table ONLY IF the sender protocol already exits
        let mut merged = ctx
            .arp_table
            .update_only(arp.source_mac(), arp.source_addr());

        if ctx.ipv4_addresses.contains(arp.target_addr()) {
            if !merged {
                ctx.arp_table
                    .update_or_insert(arp.source_mac(), arp.source_addr());
                merged = true;
            }

            if arp.operation() == Operation::Request {
                let reply = arp.reply(ctx.mac_addr, arp.target_addr());
                if let Err(err) = Self::send(ctx, reply.target_mac(), EtherType::ARP, &reply) {
                    // Sending the ARP Response - if this doesn't work not much we can do
                    error!("Failed to send ARP reply: {}", err);
                }
            }
        }

        if merged {
            Self::dequeue_pending_ipv4(ctx, managers, arp.source_mac(), arp.source_addr());
        }
    }

    pub fn perform_arp_timers(
        ctx: &mut InterfaceContext,
        managers: &mut Managers,
    ) -> Option<std::time::Instant> {
        let mut deadline: Option<std::time::Instant> = None;

        for (ip, source) in ctx.arp_table.pending() {
            match ctx.arp_table.request(ip, source) {
                ArpState::PendingWait {
                    deadline: request_deadline,
                } => {
                    deadline = deadline
                        .map(|dl| dl.min(request_deadline))
                        .or(Some(request_deadline));
                }
                ArpState::PendingRetry { source } => {
                    _ = Self::send_arp_request(ctx, ip, source);
                }
                // Look, I don't quite know how we would hit ResolvedStale here, but...
                ArpState::Resolved(mac) | ArpState::ResolvedStale(mac) => {
                    Self::dequeue_pending_ipv4(ctx, managers, mac, ip);
                    // TODO Whatever else is needed now the address has been resovled - not sure what that is
                }
                // Restart is when the Timeout has gone stale or the Resolved has gone through stale out the other side
                ArpState::Timeout | ArpState::Restart => {
                    if let Some(queue) = ctx.ipv4_send_buffer.remove(&ip) {
                        for (ipv4header, payload) in queue {
                            managers.forward_async_error(
                                ctx,
                                LocalSendError {
                                    error: ArpTimeout,
                                    ipv4header,
                                    datagram: payload[..ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH]
                                        .try_into()
                                        .unwrap_or([0u8; 8]),
                                },
                            );
                        }
                    }
                }
            }
        }

        deadline
    }

    pub fn dequeue_pending_ipv4(
        ctx: &mut InterfaceContext,
        managers: &mut Managers,
        mac: MacAddr,
        ipv4addr: Ipv4Addr,
    ) {
        if let Some(queue) = ctx.ipv4_send_buffer.remove(&ipv4addr) {
            trace!(
                "resolved {} draining {} pending messages",
                ipv4addr,
                queue.len()
            );

            for pending in queue {
                if let Err(error) = Self::send(ctx, mac, EtherType::IPv4, &pending) {
                    managers.forward_async_error(
                        ctx,
                        AsyncSendError::LocalSendError {
                            error,
                            ipv4header: pending.0,
                            // We should not have accepted an IPv4 message <8 bytes but hey
                            datagram: pending.1[0..8].try_into().unwrap_or([0u8; 8]),
                        },
                    );
                }
            }
        }
    }
}
