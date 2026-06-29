use crate::poller::{Poller, PollerTimeoutError, ReadyState, ReadyTokensByBits};
use crate::runtime::UdpSocket;
use crate::runtime::interface::Interface;
use crate::write_to_buffer::WriteToBuffer;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Instant;
use thiserror::Error;
use tracing::error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct DHCPv4Client {
    interface: Interface,

    state: state::ClientState,
}

/// DHCP messages from a client to a server are sent to the 'DHCP server' port (67)
/// [RFC2131 Page 23](https://datatracker.ietf.org/doc/html/rfc2131#page-23)
pub const SERVER_PORT: u16 = 67;
/// DHCP messages from a server to a client are sent to the 'DHCP client' port (68)
/// [RFC2131 Page 23](https://datatracker.ietf.org/doc/html/rfc2131#page-23)
pub const CLIENT_PORT: u16 = 68;

impl DHCPv4Client {
    #[must_use]
    pub fn new(interface: Interface) -> Self {
        let mac_addr = interface.mac_addr();
        Self {
            interface,
            state: state::ClientState::new(mac_addr),
        }
    }

    pub fn run(&mut self) -> Result<(), Error> {
        let mut poller = Poller::default();

        let mut udp = self
            .interface
            .bind_udp(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, CLIENT_PORT))?;
        let token = poller.register(&mut udp)?;

        let mut buf = vec![0; 1480];
        loop {
            let ready = match self.state.deadline(Instant::now()) {
                Some(deadline) => poller.poll_deadline(deadline),
                None => Ok(poller.poll()),
            };

            match ready {
                Err(PollerTimeoutError::Timeout) => {
                    Self::process_action(
                        self.state.handle_tick(Instant::now()),
                        &mut udp,
                        &mut buf,
                    );
                }
                Ok(mut ready) => {
                    // We know we only have one source registered, so just grab it
                    if let Some(event) = ready.next() {
                        debug_assert_eq!(event.token, token);
                        if matches!(event.state, ReadyState::Read | ReadyState::Both) {
                            self.handle_read_ready(&mut udp, &mut buf);
                        }

                        // We are intentionally ignoring ReadyState::Write as we should never need
                        // to deal with pending packet send in our DHCP client
                        // And if we do, we will just let the tiemout mechanims handle it
                    }
                }
            }
        }
    }

    fn handle_timeout(&mut self, now: Instant, udp: &mut UdpSocket, buf: &mut [u8]) {
        Self::process_action(self.state.handle_tick(now), udp, buf);
    }

    fn handle_read_ready(&mut self, udp: &mut UdpSocket, buf: &mut [u8]) {
        loop {
            match udp.recv_from(buf) {
                Ok((count, addr)) => match buf[..count].try_into() {
                    Ok(dhcp) => {
                        Self::process_action(self.state.handle_packet(dhcp), udp, buf);
                    }
                    Err(err) => {
                        error!("Failed to parse DHCP packet: {}", err);
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => error!("error {e:?} while reading"),
            }
        }
    }

    fn process_action(action: state::Action, udp: &mut UdpSocket, buf: &mut [u8]) {
        if let state::Action::SendPacket(addr, packet) = action {
            packet.write_to_buffer(&mut buf[..]);
            if let Err(err) = udp.send_to(&buf[..packet.encoded_length()], addr) {
                error!("Error sending packet {:?} to UDP server: {:?}", err, addr);
            }
        }
    }
}

mod state {
    use crate::protocols::ethernet::mac::MacAddr;
    use crate::protocols::ipv4::dhcp::DHCP;
    use crate::services::dhcpv4::SERVER_PORT;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::ops::Add;
    use std::time::{Duration, Instant};

    #[derive(Debug)]
    struct Selecting {
        transaction_id: u32,
        started_at: Instant,
    }

    /// Represents the DHCP Client state
    ///
    /// ```text
    ///  --------                               -------
    /// |        | +-------------------------->|       |<-------------------+
    /// | INIT-  | |     +-------------------->| INIT  |                    |
    /// | REBOOT |DHCPNAK/         +---------->|       |<---+               |
    /// |        |Restart|         |            -------     |               |
    ///  --------  |  DHCPNAK/     |               |                        |
    ///     |      Discard offer   |      -/Send DHCPDISCOVER               |
    /// -/Send DHCPREQUEST         |               |                        |
    ///     |      |     |      DHCPACK            v        |               |
    ///  -----------     |   (not accept.)/   -----------   |               |
    /// |           |    |  Send DHCPDECLINE |           |                  |
    /// | REBOOTING |    |         |         | SELECTING |<----+            |
    /// |           |    |        /          |           |     |DHCPOFFER/  |
    ///  -----------     |       /            -----------   |  |Collect     |
    ///     |            |      /                  |   |       |  replies   |
    /// DHCPACK/         |     /  +----------------+   +-------+            |
    /// Record lease, set|    |   v   Select offer/                         |
    /// timers T1, T2   ------------  send DHCPREQUEST      |               |
    ///     |   +----->|            |             DHCPNAK, Lease expired/   |
    ///     |   |      | REQUESTING |                  Halt network         |
    ///     DHCPOFFER/ |            |                       |               |
    ///     Discard     ------------                        |               |
    ///     |   |        |        |                   -----------           |
    ///     |   +--------+     DHCPACK/              |           |          |
    ///     |              Record lease, set    -----| REBINDING |          |
    ///     |                timers T1, T2     /     |           |          |
    ///     |                     |        DHCPACK/   -----------           |
    ///     |                     v     Record lease, set   ^               |
    ///     +----------------> -------      /timers T1,T2   |               |
    ///                +----->|       |<---+                |               |
    ///                |      | BOUND |<---+                |               |
    ///   DHCPOFFER, DHCPACK, |       |    |            T2 expires/   DHCPNAK/
    ///    DHCPNAK/Discard     -------     |             Broadcast  Halt network
    ///                |       | |         |            DHCPREQUEST         |
    ///                +-------+ |        DHCPACK/          |               |
    ///                     T1 expires/   Record lease, set |               |
    ///                  Send DHCPREQUEST timers T1, T2     |               |
    ///                  to leasing server |                |               |
    ///                          |   ----------             |               |
    ///                          |  |          |------------+               |
    ///                          +->| RENEWING |                            |
    ///                             |          |----------------------------+
    ///                              ----------
    ///           Figure 5:  State-transition diagram for DHCP clients
    /// ```
    #[derive(Debug)]
    struct ClientStateContext<S> {
        rng: fastrand::Rng,
        mac_addr: MacAddr,
        timeout: Duration,
        state: S,
    }

    #[derive(Debug)]
    pub enum ClientState {
        Init(ClientStateContext<()>),
        Selecting(ClientStateContext<Selecting>),
        Requesting,
        Bound,
        Rebinding,
        Renewing,
        Rebooting,
        InitRebooting,

        Transitioning,
    }

    #[derive(Debug)]
    pub enum Action {
        SendPacket(SocketAddrV4, DHCP),
        None,
    }

    impl ClientState {
        pub fn new(mac_addr: MacAddr) -> Self {
            Self::Init(ClientStateContext {
                state: (),
                mac_addr,
                rng: fastrand::Rng::new(),
            })
        }

        pub const fn new_seeded(mac_addr: MacAddr, rng: fastrand::Rng) -> Self {
            Self::Init(ClientStateContext {
                state: (),
                mac_addr,
                rng,
            })
        }

        pub fn deadline(&mut self, now: Instant) -> Option<Instant> {
            match self {
                // No seriously - we are supposed to wait between 1 and 10 seconds before starting
                Self::Init(init) => Some(now.add(Duration::from_secs(init.rng.u64(1..10)))),
                Self::Selecting(_) => None,
                Self::Requesting => None,
                Self::Bound => None,
                Self::Rebinding => None,
                Self::Renewing => None,
                Self::Rebooting => None,
                Self::InitRebooting => None,
                Self::Transitioning => None,
            }
        }

        pub fn handle_tick(&mut self, now: Instant) -> Action {
            if matches!(self, Self::Transitioning) {
                // we should not be here... this is messed up - maybe we should assert? or at least debug_assert?
                return Action::None;
            }

            let current = std::mem::replace(self, Self::Transitioning);

            match current {
                Self::Init(state) => self.transition_init_to_selecting(state, now),
                // ClientState::Selecting(_) => {}
                // ClientState::Requesting => {}
                // ClientState::Bound => {}
                // ClientState::Rebinding => {}
                // ClientState::Renewing => {}
                // ClientState::Rebooting => {}
                // ClientState::InitRebooting => {}
                Self::Transitioning => unreachable!(),
                _ => {
                    // Temp fall-through
                    *self = current;
                    Action::None
                }
            }
        }

        pub fn handle_packet(&mut self, packet: DHCP) -> Action {
            Action::None
        }
    }

    impl ClientState {
        fn transition_init_to_selecting(
            &mut self,
            mut state: ClientStateContext<()>,
            now: Instant,
        ) -> Action {
            let transaction_id = state.rng.u32(..);
            let started_at = now;

            let discover =
                DHCP::discover(transaction_id, started_at, state.mac_addr, None, None, None);

            *self = Self::Selecting(ClientStateContext {
                state: Selecting {
                    transaction_id,
                    started_at,
                },
                mac_addr: state.mac_addr,
                rng: state.rng,
            });

            Action::SendPacket(
                SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT),
                discover,
            )
        }
    }
}
