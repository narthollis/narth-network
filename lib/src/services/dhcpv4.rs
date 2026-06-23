use crate::poller::{Poller, ReadyState};
use crate::protocols::ipv4::dhcp::DHCP;
use crate::runtime::interface::Interface;
use std::net::{Ipv4Addr, SocketAddrV4};
use thiserror::Error;
use tracing::error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Debug)]
enum ClientState {
    Init,
    Selecting,
    Requesting,
    Bound,
    Rebinding,
    Renewing,
    Rebooting,
    InitRebooting,
}

impl ClientState {}

#[derive(Debug)]
pub struct DHCPv4Client {
    interface: Interface,

    state: ClientState,
}

impl DHCPv4Client {
    #[must_use]
    pub const fn new(interface: Interface) -> Self {
        Self {
            interface,
            state: ClientState::Init,
        }
    }

    pub fn run(&mut self) -> Result<(), Error> {
        let mut poller = Poller::default();

        let mut udp = self
            .interface
            .bind_udp(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68))?;
        let token = poller.register(&mut udp)?;

        // we probably need to send some kind of kick-off message

        loop {
            let ready = poller.poll(); // this will probably need to become a poll_timeout so we can run the needed timers
            for event in ready {
                // if it isn't this then i'm a little confused
                if event.token == token {
                    match event.state {
                        ReadyState::Read => {
                            let mut b = vec![0u8; 1480]; // TODO work out the mtu betterr
                            match udp.recv_from(&mut b) {
                                Ok((count, addr)) => {
                                    let dhcp: DHCP = match b[..count].try_into() {
                                        Ok(dhcp) => dhcp,
                                        Err(err) => {
                                            error!("Failed to parse DHCP packet: {}", err);
                                            break;
                                        }
                                    };
                                    dbg!(dhcp);
                                }
                                Err(e) => error!("error {e:?} while reading"),
                            }
                        }
                        ReadyState::Write => {}
                        ReadyState::Both => {}
                    }
                }
            }
        }
    }
}
