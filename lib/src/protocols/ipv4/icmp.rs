use crate::common;
use crate::common::{WriteToBuffer, err_as_eof};
use crate::protocols::ipv4::IPv4Header;
use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;

pub const ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH: usize = 64 / (u8::BITS as usize);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DestinationUnreachableCode {
    NetUnreachable,
    HostUnreachable,
    ProtocolUnreachable,
    PortUnreachable,
    FragmentationNeededAndDoNotFragmentSet,
    SourceRouteFailed,
}
impl TryFrom<u8> for DestinationUnreachableCode {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use DestinationUnreachableCode::*;

        match value {
            0 => Ok(NetUnreachable),
            1 => Ok(HostUnreachable),
            2 => Ok(ProtocolUnreachable),
            3 => Ok(PortUnreachable),
            4 => Ok(FragmentationNeededAndDoNotFragmentSet),
            5 => Ok(SourceRouteFailed),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid Destination Unreachable code",
            )),
        }
    }
}

impl From<DestinationUnreachableCode> for u8 {
    fn from(value: DestinationUnreachableCode) -> Self {
        use DestinationUnreachableCode::*;

        match value {
            NetUnreachable => 0,
            HostUnreachable => 1,
            ProtocolUnreachable => 2,
            PortUnreachable => 3,
            FragmentationNeededAndDoNotFragmentSet => 4,
            SourceRouteFailed => 5,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct DestinationUnreachableMessage {
    pub code: DestinationUnreachableCode,
    pub ipv4header: IPv4Header,
    pub datagram: [u8; ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH],
}

impl TryFrom<(u8, bytes::Bytes)> for DestinationUnreachableMessage {
    type Error = std::io::Error;

    fn try_from((code, bytes): (u8, bytes::Bytes)) -> Result<Self, Self::Error> {
        let ipv4header = IPv4Header::from_bytes(&bytes).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "ICMP Payload truncated parsing IPv4 Header",
            ),
            _ => std::io::Error::new(
                e.kind(),
                format!("ICMP Payload IPv4 Header Parse Failed: {}", e),
            ),
        })?;

        let header_len = ipv4header.encoded_length();
        if bytes.len() < header_len + ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "ICMP Payload truncated, missing or truncated datagram start",
            ));
        }

        let datagram = bytes[header_len..header_len + ICMP_PAYLOAD_DATAGRAM_PORTION_LENGTH]
            .try_into()
            .map_err(err_as_eof("ICMP Payload truncated datagrams"))?;

        Ok(DestinationUnreachableMessage {
            ipv4header,
            datagram,
            code: code.try_into()?,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum TimeExceededCode {
    TimeToLiveExceededInTransit,
    FragmentReassemblyTimeExceeded,
}
impl TryFrom<u8> for TimeExceededCode {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use TimeExceededCode::*;
        match value {
            0 => Ok(TimeToLiveExceededInTransit),
            1 => Ok(FragmentReassemblyTimeExceeded),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid Time Exceeded Code",
            )),
        }
    }
}

impl From<TimeExceededCode> for u8 {
    fn from(value: TimeExceededCode) -> Self {
        use TimeExceededCode::*;
        match value {
            TimeToLiveExceededInTransit => 0,
            FragmentReassemblyTimeExceeded => 1,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TimeExceededMessage {
    code: TimeExceededCode,
    data: bytes::Bytes,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParameterProblemMessage {
    pointer: u8,
    data: bytes::Bytes,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum RedirectMessageCode {
    Network,
    Host,
    ServiceAndNetwork,
    ServiceAndHost,
}
impl TryFrom<u8> for RedirectMessageCode {
    type Error = std::io::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use RedirectMessageCode::*;
        match value {
            0 => Ok(Network),
            1 => Ok(Host),
            2 => Ok(ServiceAndNetwork),
            3 => Ok(ServiceAndHost),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid Redirect Message Code",
            )),
        }
    }
}

impl From<RedirectMessageCode> for u8 {
    fn from(value: RedirectMessageCode) -> Self {
        match value {
            RedirectMessageCode::Network => 0,
            RedirectMessageCode::Host => 1,
            RedirectMessageCode::ServiceAndNetwork => 2,
            RedirectMessageCode::ServiceAndHost => 4,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RedirectMessage {
    code: RedirectMessageCode,
    gateway: Ipv4Addr,
    data: bytes::Bytes,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct EchoMessage {
    identifier: u16,
    sequence_number: u16,
    data: EchoMessageData,
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum EchoMessageData {
    Bytes(bytes::Bytes),
    UnixLike(EchoMessageDataUnix),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct EchoMessageDataUnix {
    pub(crate) since_epoc: std::time::Duration,
    pub(crate) monotonic_instant: Option<std::time::Duration>,
}

impl EchoMessageDataUnix {
    const LENGTH: usize = 56;
    const EMPTY: [u8; Self::LENGTH] = const {
        let mut e = [0u8; Self::LENGTH];
        let mut i = 0;
        while i < e.len() {
            e[i] = i as u8;
            i += 1;
        }
        e
    };
}

impl Default for EchoMessageDataUnix {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("failed to get system time since UNIX_EPOCH");

        Self {
            since_epoc: now,
            monotonic_instant: crate::runtime::BOOT_TIME
                .get()
                .map(|x| std::time::Instant::now().duration_since(*x)),
        }
    }
}

impl WriteToBuffer for EchoMessageDataUnix {
    fn encoded_length(&self) -> usize {
        Self::LENGTH
    }

    fn write_to_buffer<B: bytes::BufMut>(&self, buffer: &mut B) {
        buffer.put_u64_ne(self.since_epoc.as_secs());
        buffer.put_u64_ne(self.since_epoc.subsec_micros() as u64);

        let mut pad_len = 56 - 16;

        if let Some(monotonic_instant) = self.monotonic_instant {
            buffer.put_u128_ne(monotonic_instant.as_nanos());

            // And we now need to pad 16 fewer bytes
            pad_len -= 16;
        }

        buffer.put_slice(Self::EMPTY[pad_len..].as_ref());
    }
}

impl TryFrom<&bytes::Bytes> for EchoMessageDataUnix {
    type Error = std::io::Error;

    /// Try and get Unix-like ping data (with the addition of our monotomic timer)
    /// But this has a very high chance of just returning junk
    /// As far as I have been able to tell there aren't any real markers
    /// So we should probably only call this on EchoReply's that we have already matched
    fn try_from(value: &bytes::Bytes) -> Result<Self, Self::Error> {
        if value.len() < Self::LENGTH {
            return std::io::Result::Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "ICMP Payload truncated parsing",
            ));
        }

        // using unwrap because we verified length above
        let sec = u64::from_ne_bytes(
            value[..8]
                .try_into()
                .expect("icmp echo parse got eof after length check"),
        );
        let micros = u64::from_ne_bytes(
            value[8..16]
                .try_into()
                .expect("icmp echo parse got eof after length check"),
        );

        let nanos: u128 = u128::from(sec) * 1_000_000_000 + u128::from(micros * 1_000);

        let since_epoc = std::time::Duration::from_nanos_u128(nanos);

        let maybe_monotonic_instant: [u8; 16] = value[16..32]
            .try_into()
            .expect("icmp echo parse got eof after length check");
        let mut monotonic_instant = None;
        if maybe_monotonic_instant != Self::EMPTY[16..32] {
            let nanos = u128::from_ne_bytes(maybe_monotonic_instant);
            // It would be great to do some extra validation here we didn't jst decode junk
            // but... I got nothin
            if nanos > 0 && nanos < std::time::Duration::MAX.as_nanos() {
                monotonic_instant = Some(std::time::Duration::from_nanos_u128(nanos));
            }
        }

        Ok(Self {
            since_epoc,
            monotonic_instant,
        })
    }
}

impl EchoMessage {
    pub const fn identifier(&self) -> u16 {
        self.identifier
    }
    pub const fn sequence_number(&self) -> u16 {
        self.sequence_number
    }
    pub fn parse_unix_data(&self) -> Result<EchoMessageDataUnix, std::io::Error> {
        match &self.data {
            EchoMessageData::UnixLike(data) => Ok(*data),
            EchoMessageData::Bytes(bytes) => bytes.try_into(),
        }
    }
}

impl TryFrom<&bytes::Bytes> for EchoMessage {
    type Error = std::io::Error;

    fn try_from(bytes: &bytes::Bytes) -> Result<Self, Self::Error> {
        Ok(Self {
            identifier: u16::from_be_bytes([bytes[4], bytes[5]]),
            sequence_number: u16::from_be_bytes([bytes[6], bytes[7]]),
            data: EchoMessageData::Bytes(bytes.slice(8..)),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ICMPMessageTypes {
    EchoReply(EchoMessage),
    DestinationUnreachable(DestinationUnreachableMessage),
    SourceQuench(bytes::Bytes),
    Redirect(RedirectMessage),
    Echo(EchoMessage),
    TimeExceeded(TimeExceededMessage),
    ParameterProblem(ParameterProblemMessage),
    // TODO the rest
}

#[derive(PartialEq, Eq, Clone)]
pub struct ICMPMessage {
    checksum: [u8; 2],
    pub message: ICMPMessageTypes,
}

impl ICMPMessage {
    #[must_use]
    pub fn new_echo_request(identifier: u16, sequence: u16) -> Self {
        Self {
            checksum: [0, 0],
            message: ICMPMessageTypes::Echo(EchoMessage {
                identifier,
                sequence_number: sequence,
                data: EchoMessageData::UnixLike(EchoMessageDataUnix::default()),
            }),
        }
    }

    pub fn echo_reply(original: &EchoMessage) -> Self {
        Self {
            checksum: [0, 0],
            message: ICMPMessageTypes::EchoReply(original.clone()),
        }
    }

    pub fn from_bytes(bytes: &bytes::Bytes) -> std::io::Result<Self> {
        #[allow(clippy::enum_glob_use)]
        use ICMPMessageTypes::*;

        if bytes.len() < 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "ICMP Payload truncated parsing",
            ));
        }

        let mut checksum = internet_checksum::Checksum::new();
        checksum.add_bytes(&bytes[..2]);
        checksum.add_bytes(&[0u8, 0u8]);
        checksum.add_bytes(&bytes[4..]);
        let checksum = checksum.checksum();
        if [bytes[2], bytes[3]] != checksum {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ICMP Payload checksum mismatch",
            ));
        }

        let checksum: [u8; 2] = [bytes[2], bytes[3]];

        let code = bytes[1];
        let data = bytes.slice(8..);

        let message = match bytes[0] {
            0 => Ok(EchoReply(bytes.try_into()?)),
            3 => Ok(DestinationUnreachable((code, data).try_into()?)),
            4 => Ok(SourceQuench(bytes.slice(8..))),
            5 => Ok(Redirect(RedirectMessage {
                code: code.try_into()?,
                gateway: Ipv4Addr::from_octets(
                    bytes[4..8]
                        .try_into()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
                ),
                data: bytes.slice(8..),
            })),
            8 => Ok(Echo(bytes.try_into()?)),
            11 => Ok(TimeExceeded(TimeExceededMessage {
                code: code.try_into()?,
                data: bytes.slice(8..),
            })),
            12 => Ok(ParameterProblem(ParameterProblemMessage {
                pointer: bytes[5],
                data: bytes.slice(8..),
            })),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid ICMP Message",
            )),
        }?;

        Ok(Self { checksum, message })
    }

    fn type_and_code_u8(&self) -> (u8, u8) {
        #[allow(clippy::enum_glob_use)]
        use ICMPMessageTypes::*;
        match &self.message {
            EchoReply(_) => (0u8, 0u8),
            DestinationUnreachable(m) => (3u8, m.code.into()),
            SourceQuench(_) => (4u8, 0u8),
            Redirect(m) => (5u8, m.code.into()),
            Echo(_) => (8u8, 0u8),
            TimeExceeded(m) => (11u8, m.code.into()),
            ParameterProblem(_) => (12u8, 0u8),
        }
    }
}

impl common::WriteToBuffer for ICMPMessage {
    fn encoded_length(&self) -> usize {
        #[allow(clippy::enum_glob_use)]
        use ICMPMessageTypes::*;

        1 // Type
            + 1 // Code
            + 2 // Checksum
            + match &self.message {
            EchoReply(m) | Echo(m) => {
                2 // Identifier
                    + 2 // Sequence
                    + match &m.data {
                    EchoMessageData::Bytes(b) => b.len(),
                    EchoMessageData::UnixLike(d) => d.encoded_length(),
                }
            }
            DestinationUnreachable(m) => {
                4 // Reserved
                    + m.ipv4header.encoded_length()
                    + m.datagram.len()
            }
            SourceQuench(m) => {
                4 // Reserved
                    + m.as_ref().len()
            }
            // 4=gateway address + data length
            Redirect(m) => {
                4 // Reserved
                    + m.data.as_ref().len()
            }
            // 4=reserved + data length
            TimeExceeded(m) => {
                4 // Reserved
                    + m.data.as_ref().len()
            }
            ParameterProblem(m) => {
                1 // Pointer
                    + 3 // Reserved
                    + m.data.as_ref().len()
            }
        }
    }

    fn write_to_buffer<B: bytes::BufMut>(&self, buffer: &mut B) {
        use ICMPMessageTypes::*;
        use bytes::BufMut;

        let mut packet = bytes::BytesMut::with_capacity(self.encoded_length());

        let (icmp_type, code) = self.type_and_code_u8();

        packet.put_u8(icmp_type);
        packet.put_u8(code);

        packet.put_u16(0x0000);

        match &self.message {
            Echo(m) | EchoReply(m) => {
                packet.put_u16(m.identifier);
                packet.put_u16(m.sequence_number);
                match &m.data {
                    EchoMessageData::Bytes(b) => packet.put_slice(b),
                    EchoMessageData::UnixLike(d) => d.write_to_buffer(&mut packet),
                }
            }
            DestinationUnreachable(m) => {
                m.ipv4header.write_to_buffer(&mut packet);
                packet.put_slice(&m.datagram);
            }
            SourceQuench(data) => packet.put_slice(data.as_ref()),
            Redirect(m) => packet.put_slice(m.data.as_ref()),
            TimeExceeded(m) => packet.put_slice(m.data.as_ref()),
            ParameterProblem(m) => packet.put_slice(m.data.as_ref()),
        };

        let mut checksum = internet_checksum::Checksum::new();
        checksum.add_bytes(&packet);
        let checksum = checksum.checksum();

        packet[2] = checksum[0];
        packet[3] = checksum[1];

        buffer.put_slice(&packet);
    }
}

impl Debug for ICMPMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use ICMPMessageTypes::*;

        let (icmp_type, code) = self.type_and_code_u8();

        let mut d = f.debug_struct("ICMPMessage");
        d.field("type", &icmp_type);
        match &self.message {
            DestinationUnreachable(m) => d.field("code", &m.code),
            Redirect(m) => d.field("code", &m.code),
            TimeExceeded(m) => d.field("code", &m.code),
            _ => d.field("code", &code),
        };

        d.field(
            "checksum",
            &(u16::from_be_bytes([self.checksum[0], self.checksum[1]])),
        );

        match &self.message {
            Echo(m) | EchoReply(m) => {
                d.field("identifier", &m.identifier)
                    .field("sequence_number", &m.sequence_number)
                    .field(
                        "data",
                        match &m.data {
                            EchoMessageData::Bytes(b) => b,
                            EchoMessageData::UnixLike(d) => d,
                        },
                    );
            }
            DestinationUnreachable(m) => {
                d.field("ipv4_header", &m.ipv4header);
                d.field("datagram", &m.datagram);
            }
            SourceQuench(m) => {
                d.field("data", &m.as_ref());
            }
            Redirect(m) => {
                d.field("data", &m.data.as_ref());
            }
            TimeExceeded(m) => {
                d.field("data", &m.data.as_ref());
            }
            ParameterProblem(m) => {
                d.field("data", &m.data.as_ref());
            }
        }

        d.field("len()", &(self.encoded_length()));

        d.finish()
    }
}
