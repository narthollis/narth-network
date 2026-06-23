use std::fmt::Formatter;

#[derive(Eq, PartialEq, Clone, Copy, Hash)]
pub struct MacAddr(u8, u8, u8, u8, u8, u8);

pub const BROADCAST: MacAddr = MacAddr(255, 255, 255, 255, 255, 255);

impl MacAddr {
    pub const LENGTH: usize = 6;

    #[must_use]
    #[allow(clippy::many_single_char_names)]
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self(a, b, c, d, e, f)
    }

    #[must_use]
    pub const fn from_octets(bytes: [u8; 6]) -> Self {
        Self(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    }

    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        self.eq(&BROADCAST)
    }

    #[must_use]
    pub const fn octets(&self) -> [u8; 6] {
        [self.0, self.1, self.2, self.3, self.4, self.5]
    }
}

impl std::fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MacAddr")
            .field(&format_args!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                self.0, self.1, self.2, self.3, self.4, self.5
            ))
            .finish()
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0, self.1, self.2, self.3, self.4, self.5
        )
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(bytes: [u8; 6]) -> Self {
        Self(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TryFromSliceError(());

impl std::fmt::Display for TryFromSliceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        "could not create MacAddr from slice".fmt(f)
    }
}

impl std::error::Error for TryFromSliceError {}

impl TryFrom<&[u8]> for MacAddr {
    type Error = TryFromSliceError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 6 {
            return Err(TryFromSliceError(()));
        }
        Ok(Self(
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        ))
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> [u8; 6] {
        [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]
    }
}
