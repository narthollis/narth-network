enum PingResultStatus {
    Success(std::time::Duration),
    Timeout,
    Unreachable, // TODO expand this to carry Host/Network/HostAndNetwork/etc.
}

struct PingResult {
    pub sequence: u16,
    pub target: std::net::Ipv4Addr,
    pub status: PingResultStatus,
}

struct PingSession {
    reply_rx: std::sync::mpsc::Receiver<PingResult>,
    stop_tx: std::sync::mpsc::Sender<()>,
}

impl PingSession {
    pub fn recv(&self) -> Option<PingResult> {
        self.reply_rx.recv().ok()
    }

    pub fn stop(&self) {
        _ = self.stop_tx.send(());
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
        _ = self.stop_tx.send(());
    }
}
