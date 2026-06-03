use crate::protocols::ipv4::IPv4Header;
use crate::protocols::ipv4::icmp::{DestinationUnreachableMessage, EchoMessage, ICMPMessage};
use std::ops::Sub;
use std::time::Instant;

/* region Public */
#[derive(Debug)]
pub enum PingResultStatus {
    Success(Option<std::time::Duration>),
    Timeout,
    Unreachable(&'static str), // TODO expand this to carry Host/Network/HostAndNetwork/etc.
}

#[derive(Debug)]
pub struct PingResult {
    pub sequence: usize,
    pub target: std::net::Ipv4Addr,
    pub status: PingResultStatus,
}

pub struct PingSession {
    reply_rx: std::sync::mpsc::Receiver<(usize, PingResultStatus)>,
    control_tx: std::sync::mpsc::Sender<ControlMessage>,
    pub target: std::net::Ipv4Addr,
    key: PingEntryKey,
}

impl PingSession {
    // TODO add fun stuff like impl Display and averaging and max/min etc.
    pub fn recv(&mut self) -> Option<PingResult> {
        self.reply_rx
            .try_recv()
            .ok()
            .map(|(sequence, status)| PingResult {
                sequence,
                status,
                target: self.target,
            })
    }

    pub fn stop(&self) {
        _ = self.control_tx.send(ControlMessage::Stop(self.key));
    }
}

impl Iterator for PingSession {
    type Item = PingResult;

    fn next(&mut self) -> Option<Self::Item> {
        self.reply_rx
            .recv()
            .ok()
            .map(|(sequence, status)| PingResult {
                sequence,
                status,
                target: self.target,
            })
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
struct PingManagerEntry {
    target: std::net::Ipv4Addr,
    identifier: u16,
    count: Option<usize>,
    interval: std::time::Duration,

    sent_count: usize,
    last_sent: Option<std::time::Instant>,
    pending: std::collections::VecDeque<(u16, std::time::Instant)>,

    recv_tx: std::sync::mpsc::Sender<(usize, PingResultStatus)>,
    timeout: std::time::Duration,
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
        count: Option<usize>,
        interval: std::time::Duration,
    ) -> PingSession {
        let (recv_tx, recv_rx) = std::sync::mpsc::channel();

        let identifier = {
            let mut identifier = fastrand::u16(..);
            while self
                .sessions
                .contains_key(&PingEntryKey(target, identifier))
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
            timeout: std::time::Duration::from_secs(1),

            sent_count: 0,
            last_sent: None,
            pending: std::collections::VecDeque::default(),

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

        let request = self
            .sessions
            .iter_mut()
            .filter_map(|(_, entry)| Self::process_timers_session(entry, now))
            .collect();

        self.garbage_collect();

        request
    }

    fn process_timers_session(
        entry: &mut PingManagerEntry,
        now: std::time::Instant,
    ) -> Option<(std::net::Ipv4Addr, ICMPMessage)> {
        // Process Timeouts
        while let Some((_, sent_at)) = entry.pending.front() {
            if (now - *sent_at) > entry.timeout {
                let (seq, _) = entry.pending.pop_front().unwrap();
                let _ = entry.recv_tx.send((
                    Self::unwrap_sequence(seq, entry.sent_count),
                    PingResultStatus::Timeout,
                ));
            } else {
                // If this ping hasn't timed out the other's won't have either
                break;
            }
        }

        // Check if we still have stuff to send (sent_count < count) AND if the send interval has passed
        // And now let's find out pending!
        if match entry.count {
            Some(c) => entry.sent_count < c,
            None => true,
        } && match entry.last_sent {
            Some(last_sent) => now.duration_since(last_sent) > entry.interval,
            None => true,
        } {
            let sequence = entry.sent_count as u16;

            entry.pending.push_back((sequence, now));
            entry.last_sent = Some(now);
            entry.sent_count = entry.sent_count.wrapping_add(1);

            tracing::trace!("created new ping request to {}", entry.target);
            Some((
                entry.target,
                ICMPMessage::new_echo_request(entry.identifier, sequence),
            ))
        } else {
            None
        }
    }

    pub(crate) fn on_echo_reply(&mut self, ipv4header: IPv4Header, message: &EchoMessage) {
        let target = ipv4header.source_address();
        let identifier = message.identifier();

        if let Some(session) = self.sessions.get_mut(&PingEntryKey(target, identifier))
            && let Some(index) = session
                .pending
                .iter()
                .position(|(s, _)| *s == message.sequence_number())
        {
            _ = session.pending.remove(index);

            let duration = message.parse_unix_data().ok().and_then(|data| {
                data.monotonic_instant.map(|m| {
                    {
                        crate::runtime::BOOT_TIME
                            .get()
                            .map(|boot| Instant::now().duration_since(*boot).sub(m))
                    }
                    .unwrap_or_else(|| {
                        println!("from system");
                        std::time::SystemTime::now()
                            .duration_since(std::time::SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .sub(data.since_epoc)
                    })
                })
            });

            _ = session.recv_tx.send((
                Self::unwrap_sequence(message.sequence_number(), session.sent_count),
                PingResultStatus::Success(duration),
            ));
        }

        self.garbage_collect();
    }

    pub(crate) fn on_unreachable(&mut self, message: &DestinationUnreachableMessage) {
        eprintln!("DestinationUnreachable={:?}", message);
    }

    pub fn garbage_collect(&mut self) {
        self.sessions
            .retain(|_, entry|
                match entry.count {
                    Some(count) => entry.sent_count < count,
                    None => true
                } || !entry.pending.is_empty()
            );
    }

    fn unwrap_sequence(sequence: u16, sent: usize) -> usize {
        // Compute shorted significant distance from sent count for the current sequence

        // Intentionally truncate the total sent to u16
        let sent_u16 = sent as u16;

        // Compute the +/- distance on the u16 "ring"
        let diff = sequence.wrapping_sub(sent_u16) as i16;

        match diff {
            // sequence is ahead of send - so add diff to the counter to get the sequence
            // -- I'm not sure how this would ever be > 0 but match that for completeness also
            0.. => sent.wrapping_add(diff as usize),
            // sequence is (as expected) behind so use unsinged_abs to turn the i16 into a clean u16
            // with the same logical value (-1 -> 1) then us a wrapping sub on our usize to get the
            // corrected sequence
            ..0 => sent.wrapping_sub(diff.unsigned_abs() as usize),
        }
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
