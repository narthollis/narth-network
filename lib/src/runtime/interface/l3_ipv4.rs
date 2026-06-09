use crate::protocols::ipv4::icmp::{ICMPMessage, ICMPMessageTypes};
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header};
use crate::runtime::interface::l4_managers::Managers;
use crate::runtime::interface::{AsyncSendError, InterfaceContext, SendError, SendResult};
use crate::write_to_buffer::WriteToBuffer;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Deref;
use tracing::{debug, info, trace, trace_span};

#[derive(Debug)]
pub(super) struct IPv4Handler {}

impl IPv4Handler {
    pub fn recv(ctx: &mut InterfaceContext, managers: &mut Managers, bytes: &bytes::Bytes) {
        let ip = match IPv4Header::from_bytes(&bytes) {
            Ok(ip) => ip,
            Err(e) => {
                debug!("failed to parse l3_ipv4 header: {}", e);
                return;
            }
        };
        if ip.is_fragmented() {
            trace!("dropping fragmented IPv4");
            return;
        }

        let payload = &bytes.slice(ip.encoded_length()..ip.total_length());

        trace_span!(
            "recv l3_ipv4",
            ipv4_source = ip.source_address().to_string(),
            ipv4_destination = ip.destination_address().to_string()
        );
        trace!("Incoming IPv4 header: {:?}", ip);

        match ip.protocol() {
            IPProtocolTypes::ICMP => Self::recv_icmp(ctx, managers, ip, payload),
            IPProtocolTypes::UDP => managers.udp_manager.recv(
                IpAddr::V4(*ip.source_address()),
                IpAddr::V4(*ip.destination_address()),
                payload,
            ),
            IPProtocolTypes::TCP => {
                // todo tcp
            }
            IPProtocolTypes::Other(protocol) => {
                info!("Received IPv4 message for {protocol}");
                // protocol we don't care about so drop it
            }
        };
    }

    fn recv_icmp(
        ctx: &mut InterfaceContext,
        managers: &mut Managers,
        ipv4_header: IPv4Header,
        payload: &bytes::Bytes,
    ) {
        let icmp = match ICMPMessage::from_bytes(payload) {
            Ok(icmp) => icmp,
            Err(e) => {
                debug!("failed to parse icmp message: {}", e);
                return;
            }
        };
        trace!("Incoming IPv4 ICMP: {:?}", icmp);

        match &icmp.message {
            ICMPMessageTypes::Echo(echo) => {
                let echo_reply = ICMPMessage::echo_reply(echo);

                // We don't really care if we fail to send the echo reply
                _ = IPv4Handler::send(
                    ctx,
                    ipv4_header.source_address(),
                    ipv4_header.destination_address(),
                    IPProtocolTypes::ICMP,
                    &echo_reply,
                );
            }
            ICMPMessageTypes::EchoReply(reply) => {
                managers.ping_manager.on_echo_reply(ipv4_header, reply);
            }
            ICMPMessageTypes::DestinationUnreachable(m) => {
                managers.forward_async_error(ctx, AsyncSendError::ICMPUnreachable(*m));
            }
            _ => {
                // TODO we need to parse the identifying data out of the control message's data and then
                // forward it to the protocol manager
                eprintln!("CONTROL MESSAGE: {icmp:?}");
            }
        }
    }

    pub fn send(
        ctx: &mut InterfaceContext,
        destination: &Ipv4Addr,
        source: &Ipv4Addr,
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
        if (payload.encoded_length() + IPv4Header::MIN_LENGTH) > ctx.mtu {
            return Err(SendError::PayloadTooLarge {
                max_size: ctx.mtu - IPv4Header::MIN_LENGTH,
            });
        }

        let payload = {
            let mut buff = bytes::BytesMut::with_capacity(payload.encoded_length());
            payload.write_to_buffer(&mut buff);
            buff.freeze()
        };
        let payload_len: u16 = payload.len().try_into().expect("payload length overflow");

        let Some(route) = ctx.ipv4_route_table.lookup(destination) else {
            return Err(SendError::NoRouteToHost);
        };
        let source = source.or_unspecified(route.source);

        let header = IPv4Header::new(protocol, source, *destination, payload_len);

        let next_hop = route.next_hop.unwrap_or(*destination);

        super::l2_ethernet::EthernetHandler::send_ipv4(ctx, next_hop, source, header, payload)
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
