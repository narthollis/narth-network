use crate::poller::{Poller, ReadyState};
use crate::runtime::interface::Interface;
use std::net::{Ipv4Addr, SocketAddrV4};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct DHCPv4Client {
    interface: Interface,
}

impl DHCPv4Client {
    #[must_use]
    pub const fn new(interface: Interface) -> Self {
        Self { interface }
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
                        ReadyState::Read => udp.recv_from(),
                        ReadyState::Write => {}
                        ReadyState::Both => {}
                    }
                }
            }
        }
    }
}
