use crate::protocols::ipv4::icmp::{DestinationUnreachableMessage, EchoMessage, ICMPMessage};

/* region Public */
enum PingResultStatus {
    Success(std::time::Duration),
    Timeout,
    Unreachable(&'static str), // TODO expand this to carry Host/Network/HostAndNetwork/etc.
}

pub struct PingResult {
    pub sequence: u16,
    pub target: std::net::Ipv4Addr,
    pub status: PingResultStatus,
}

pub struct PingSession {
    reply_rx: std::sync::mpsc::Receiver<PingResult>,
    control_tx: std::sync::mpsc::Sender<ControlMessage>,
    pub target: std::net::Ipv4Addr,
    key: PingEntryKey,
}

impl PingSession {
    pub fn recv(&self) -> Option<PingResult> {
        self.reply_rx.recv().ok()
    }

    pub fn stop(&self) {
        _ = self.control_tx.send(ControlMessage::Stop(self.key));
    }
}

impl Iterator for PingSession {
    type Item = PingResult;

    fn next(&mut self) -> Option<Self::Item> {
        self.recv()
    }
}

impl Drop for PingSession {
    fn drop(&mut self) {
        _ = self.control_tx.send(ControlMessage::Stop(self.key));
    }
}
/* endregion */

/* region Control */
enum ControlMessage {
    // Pause(PingEntryKey),
    // Resume(PingEntryKey),
    // AdjustDelay(PingEntryKey, std::time::Duration),
    Stop(PingEntryKey),
}

/* endregion */

#[derive(Debug)]
struct SentPing {
    sent_at: std::time::Instant,
}

#[derive(Debug)]
struct PingManagerEntry {
    target: std::net::Ipv4Addr,
    identifier: u16,
    count: u16,
    interval: std::time::Duration,

    last_sent: Option<std::time::Instant>,
    pending: std::collections::HashMap<u16, SentPing>,

    recv_tx: std::sync::mpsc::Sender<PingResult>,
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy)]
struct PingEntryKey(std::net::Ipv4Addr, u16);

#[derive(Debug)]
pub(crate) struct PingManager {
    sessions: std::collections::HashMap<PingEntryKey, PingManagerEntry>,
    control_rx: std::sync::mpsc::Receiver<ControlMessage>,
    control_tx: std::sync::mpsc::Sender<ControlMessage>,
}

impl PingManager {
    pub(crate) fn ping(
        &mut self,
        target: std::net::Ipv4Addr,
        count: u16,
        interval: std::time::Duration,
    ) -> PingSession {
        let (recv_tx, recv_rx) = std::sync::mpsc::channel();

        let identifier = {
            let mut identifier = fastrand::u16(..);
            while self
                .sessions
                .get(&PingEntryKey(target, identifier))
                .is_some()
            {
                identifier = fastrand::u16(..);
            }
            identifier
        };

        let entry = PingManagerEntry {
            target,
            identifier,
            count,
            interval,

            last_sent: None,
            pending: std::collections::HashMap::default(),

            recv_tx,
        };

        self.sessions
            .insert(PingEntryKey(target, identifier), entry);

        PingSession {
            control_tx: self.control_tx.clone(),
            reply_rx: recv_rx,
            target,
            key: PingEntryKey(target, identifier),
        }
    }

    pub(crate) fn perform_timers(&mut self) -> Vec<(std::net::Ipv4Addr, ICMPMessage)> {
        while let Ok(control_message) = self.control_rx.try_recv() {
            match control_message {
                ControlMessage::Stop(key) => {
                    self.sessions.remove(&key);
                }
            }
        }

        let now = std::time::Instant::now();

        self.sessions
            .values_mut()
            .filter_map(|(entry)| {
                if match entry.last_sent {
                    Some(last_sent) => now - last_sent > entry.interval,
                    None => true,
                } {
                    entry.last_sent = Some(now);
                    entry.count += 1;

                    Some((
                        entry.target,
                        ICMPMessage::new_echo_request(Some(entry.identifier), entry.count),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    pub(crate) fn on_echo_reply(&mut self, message: &EchoMessage) {}

    pub(crate) fn on_unreachable(&mut self, message: &DestinationUnreachableMessage) {
        eprintln!("DestinationUnreachable={:?}", message);
    }
}

impl Default for PingManager {
    fn default() -> Self {
        let (control_tx, control_rx) = std::sync::mpsc::channel();
        PingManager {
            sessions: std::collections::HashMap::default(),
            control_tx,
            control_rx,
        }
    }
}
