use crate::protocols::ipv4::IPProtocolTypes;
use crate::runtime::interface::l4_managers::udp::UdpManager;
use crate::runtime::interface::{AsyncSendError, InterfaceContext};
use ping::PingManager;
use tracing::{error, warn};

pub mod ping;
pub mod udp;

#[derive(Debug, Default)]
pub struct Managers {
    pub(super) ping_manager: PingManager,
    pub(super) udp_manager: UdpManager,
}

impl Managers {
    pub fn forward_async_error(&mut self, ctx: &InterfaceContext, error: AsyncSendError) {
        let (header, datagram) = match &error {
            AsyncSendError::LocalSendError {
                ipv4header,
                datagram,
                ..
            } => (ipv4header, datagram),
            AsyncSendError::ICMPUnreachable(m) => (&m.ipv4header, &m.datagram),
        };

        match header.protocol() {
            IPProtocolTypes::ICMP => {
                let kind = datagram[0];
                let code = datagram[1];
                // let checksum = [unreachable.datagram[2], unreachable.datagram[3]];

                if kind == 8 {
                    self.ping_manager.on_async_send_error(error);
                } else {
                    warn!("ICMP unreachable for ICMP: {kind}/{code}");
                }
            }
            _ => {
                error!(
                    "Interface={interface} - Error={error:?}",
                    interface = ctx.mac_addr,
                    error = &error
                );
            }
        }
    }
}
