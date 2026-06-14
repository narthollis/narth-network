use crate::protocols::ipv4::icmp::{DestinationUnreachableCode, EchoMessage, ICMPMessage};
use crate::protocols::ipv4::{IPProtocolTypes, IPv4Header};
use crate::runtime::interface::l3_ipv4::IPv4Handler;
use crate::runtime::interface::{AsyncSendError, InterfaceContext, SendError};
use tracing::error;
/* region Public */
#[derive(Debug, Clone, Copy)]
pub enum PingResultStatus {
    Success(Option<std::time::Duration>),
    Timeout,
    Unreachable(&'static str), // TODO expand this to carry Host/Network/HostAndNetwork/etc.
}

#[derive(Debug, Clone, Copy)]
pub struct PingResult {
    pub sequence: usize,
    pub target: std::net::Ipv4Addr,
    pub status: PingResultStatus,
}

#[derive(Debug)]
pub struct PingSession {
    reply_rx: std::sync::mpsc::Receiver<(usize, PingResultStatus)>,
    control_tx: std::sync::mpsc::Sender<ControlMessage>,
    pub target: std::net::Ipv4Addr,
    key: PingEntryKey,

    #[cfg(feature = "ping-statistics")]
    pub stats: Option<hdrhistogram::Histogram<u64>>,
}

impl PingSession {
    // TODO add fun stuff like impl Display.
    pub fn try_recv(&mut self) -> Option<PingResult> {
        self.reply_rx.try_recv().ok().map(|(c, s)| self.map(c, s))
    }
    pub fn recv(&mut self) -> Option<PingResult> {
        self.reply_rx.recv().ok().map(|(c, s)| self.map(c, s))
    }

    fn map(&mut self, sequence: usize, status: PingResultStatus) -> PingResult {
        let result = PingResult {
            sequence,
            status,
            target: self.target,
        };

        #[cfg(feature = "ping-statistics")]
        if let PingResultStatus::Success(Some(duration)) = result.status {
            let histogram = self.stats.get_or_insert_with(|| {
                hdrhistogram::Histogram::new(3).expect("failed to create stats")
            });
            if let Err(err) = histogram.record(duration.as_nanos().try_into().unwrap_or(u64::MAX)) {
                error!("failed to record ping stats: {err}");
            }
        }

        result
    }

    pub fn stop(&self) {
        _ = self.control_tx.send(ControlMessage::Stop(self.key));
    }
}

#[derive(Debug)]
pub struct PingSessionIterator<'a> {
    session: &'a mut PingSession,
}
impl Iterator for PingSessionIterator<'_> {
    type Item = PingResult;
    fn next(&mut self) -> Option<Self::Item> {
        self.session.recv()
    }
}

impl<'a> IntoIterator for &'a mut PingSession {
    type Item = PingResult;
    type IntoIter = PingSessionIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PingSessionIterator { session: self }
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
pub struct PingManager {
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
            timeout: std::time::Duration::from_secs(10),

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
            stats: None,
        }
    }

    pub(crate) fn perform_timers(
        &mut self,
        sender: &mut InterfaceContext,
    ) -> Option<std::time::Instant> {
        while let Ok(control_message) = self.control_rx.try_recv() {
            match control_message {
                ControlMessage::Stop(key) => {
                    self.sessions.remove(&key);
                }
            }
        }

        let now = std::time::Instant::now();

        let deadline = self
            .sessions
            .iter_mut()
            .filter_map(|(_, entry)| Self::process_timers_session(entry, now, sender))
            .min();

        self.garbage_collect();

        deadline
    }

    fn process_timers_session(
        entry: &mut PingManagerEntry,
        now: std::time::Instant,
        sender: &mut InterfaceContext,
    ) -> Option<std::time::Instant> {
        // Process Timeouts
        while let Some((_, sent_at)) = entry.pending.front() {
            if (now - *sent_at) > entry.timeout {
                let (seq, _) = entry
                    .pending
                    .pop_front()
                    .expect("already checked front item now missing");
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
        if entry.count.is_none_or(|count| entry.sent_count < count) {
            if entry
                .last_sent
                .is_none_or(|last_sent| now.duration_since(last_sent) > entry.interval)
            {
                // Intentionally truncate sent-count to u16 sequence
                #[allow(clippy::cast_possible_truncation)]
                let sequence = entry.sent_count as u16;

                let mut request = ICMPMessage::new_echo_request(entry.identifier, sequence);
                request.compute_checksum_and_update();

                if IPv4Handler::send(
                    sender,
                    std::net::Ipv4Addr::UNSPECIFIED,
                    entry.target,
                    IPProtocolTypes::ICMP,
                    request,
                )
                .is_ok()
                {
                    entry.pending.push_back((sequence, now));
                    entry.last_sent = Some(now);
                    entry.sent_count = entry.sent_count.wrapping_add(1);
                    Some(now + entry.timeout)
                } else {
                    // We failed to send when we needed to
                    Some(now)
                }
            } else {
                Some(entry.last_sent.expect("unreachable") + entry.interval)
            }
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
                data.monotonic_instant.and_then(|m| {
                    {
                        crate::runtime::BOOT_TIME.get().and_then(|boot| {
                            std::time::Instant::now()
                                .duration_since(*boot)
                                .checked_sub(m)
                        })
                    }
                    .or_else(|| {
                        println!("from system");
                        std::time::SystemTime::now()
                            .duration_since(std::time::SystemTime::UNIX_EPOCH)
                            .expect("failed to get system time since UNIX_EPOCH")
                            .checked_sub(data.since_epoc)
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

    pub(crate) fn on_async_send_error(&mut self, message: AsyncSendError) {
        let (header, datagram) = match &message {
            AsyncSendError::LocalSendError {
                ipv4header,
                datagram,
                ..
            } => (ipv4header, datagram),
            AsyncSendError::ICMPUnreachable(m) => (&m.ipv4header, &m.datagram),
        };

        let kind = datagram[0];
        let code = datagram[1];
        // let checksum = [message.datagram[2], message.datagram[3]];
        if kind != 8 || code != 0 {
            return;
        }

        let identifier = u16::from_be_bytes([datagram[4], datagram[5]]);
        let sequence_number = u16::from_be_bytes([datagram[6], datagram[7]]);

        if let Some(session) = self
            .sessions
            .get_mut(&PingEntryKey(header.destination_address(), identifier))
        {
            if let Some(pending) = session.pending.iter().position(|e| e.0 == sequence_number) {
                session.pending.remove(pending);
            }
            _ = session.recv_tx.send((
                Self::unwrap_sequence(sequence_number, session.sent_count),
                PingResultStatus::Unreachable(match message {
                    AsyncSendError::LocalSendError { error, .. } => match error {
                        SendError::ArpTimeout => "ARP Timeout",
                        _ => "Send Error",
                    },
                    AsyncSendError::ICMPUnreachable(unreachable) => match unreachable.code {
                        DestinationUnreachableCode::NetUnreachable => "network unreachable",
                        DestinationUnreachableCode::HostUnreachable => "host unreachable",
                        DestinationUnreachableCode::ProtocolUnreachable => "protocol unreachable",
                        DestinationUnreachableCode::PortUnreachable => "port unreachable",
                        DestinationUnreachableCode::FragmentationNeededAndDoNotFragmentSet => {
                            "fragment need and do not fragment set"
                        }
                        DestinationUnreachableCode::SourceRouteFailed => "source route failed",
                    },
                }),
            ));
        }
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

    const fn unwrap_sequence(sequence: u16, sent: usize) -> usize {
        // Compute shorted significant distance from sent count for the current sequence

        // Intentionally truncate the total sent to u16
        #[allow(clippy::cast_possible_truncation)]
        let sent_u16 = sent as u16;

        // Compute the +/- distance on the u16 "ring"
        let diff = sequence.wrapping_sub(sent_u16).cast_signed();

        match diff {
            // sequence is ahead of send - so add diff to the counter to get the sequence
            // -- I'm not sure how this would ever be > 0 but match that for completeness also
            0.. => sent.wrapping_add(diff.cast_unsigned() as usize),
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
        Self {
            sessions: std::collections::HashMap::default(),
            control_tx,
            control_rx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_sequence_match() {
        assert_eq!(PingManager::unwrap_sequence(0, 0), 0);
        assert_eq!(PingManager::unwrap_sequence(500, 500), 500);
        assert_eq!(PingManager::unwrap_sequence(65535, 65535), 65535);

        // Exact match but sent has wrapped exactly once (1 epoch in)
        assert_eq!(PingManager::unwrap_sequence(0, 65536), 65536);
    }

    #[test]
    fn test_sequence_behind_no_wrap() {
        // Sequence is lagging slightly behind sent
        assert_eq!(PingManager::unwrap_sequence(10, 15), 10);
        assert_eq!(PingManager::unwrap_sequence(65520, 65530), 65520);

        // High epoch: Sent is 131080 (2 * 65536 + 8), sequence is 2
        assert_eq!(PingManager::unwrap_sequence(2, 131_080), 131_074);
    }

    #[test]
    fn test_sequence_ahead_no_wrap() {
        // Sequence is slightly ahead of sent (e.g. tracking missed messages)
        assert_eq!(PingManager::unwrap_sequence(15, 10), 15);
        assert_eq!(PingManager::unwrap_sequence(65530, 65520), 65530);

        // High epoch: Sent is 131074, sequence is 8
        assert_eq!(PingManager::unwrap_sequence(8, 131_074), 131_080);
    }

    #[test]
    fn test_sequence_behind_with_wrap() {
        // Sent has just rolled over the u16 boundary to 65536 (u16 == 0)
        // Sequence is lagging behind, still at the end of the previous epoch
        assert_eq!(PingManager::unwrap_sequence(65530, 65536), 65530);

        // Sent is at 65540 (u16 == 4), sequence is lagging at 65530
        // Expected logical value is 65530
        assert_eq!(PingManager::unwrap_sequence(65530, 65540), 65530);

        // High epoch: Sent wrapped 100 times (6,553,600) + 5
        let sent = (65536 * 100) + 5;
        // Sequence is lagging by 10, so it's on the previous u16 boundary
        assert_eq!(PingManager::unwrap_sequence(65531, sent), sent - 10);
    }

    #[test]
    fn test_sequence_ahead_with_wrap() {
        // Sent is near the boundary at 65530
        // Sequence has rolled over the boundary to 5
        // Expected value is 65536 + 5 = 65541
        assert_eq!(PingManager::unwrap_sequence(5, 65530), 65541);

        // High epoch: Sent wrapped 100 times minus 5
        let sent = (65536 * 100) - 5;
        // Sequence is ahead by 10, rolling over the boundary
        assert_eq!(PingManager::unwrap_sequence(5, sent), sent + 10);
    }
}
