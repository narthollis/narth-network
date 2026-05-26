use crate::arp::ArpTable;
use crate::common::ChecksummingWriter;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::net::Ipv4Addr;
use tun_rs::SyncDevice;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum DestinationUnreachableCode {
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
pub struct DestinationUnreachableMessage<T> {
    code: DestinationUnreachableCode,
    data: T,
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TimeExceededMessage<T> {
    code: TimeExceededCode,
    data: T,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ParameterProblemMessage<T> {
    pointer: u8,
    data: T,
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RedirectMessage<T> {
    code: RedirectMessageCode,
    gateway: Ipv4Addr,
    data: T,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct EchoMessage<T> {
    identifier: u16,
    sequence_number: u16,
    data: T,
}

impl<'a> TryFrom<&'a [u8]> for EchoMessage<&'a [u8]> {
    type Error = std::io::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(EchoMessage {
            identifier: u16::from_be_bytes([bytes[4], bytes[5]]),
            sequence_number: u16::from_be_bytes([bytes[6], bytes[7]]),
            data: &bytes[8..],
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ICMPMessageTypes<T> {
    EchoReply(EchoMessage<T>),
    DestinationUnreachable(DestinationUnreachableMessage<T>),
    SourceQuench(T),
    Redirect(RedirectMessage<T>),
    Echo(EchoMessage<T>),
    TimeExceeded(TimeExceededMessage<T>),
    ParameterProblem(ParameterProblemMessage<T>),
    // TODO the rest
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct ICMPMessage<T> {
    checksum: [u8; 2],
    pub message: ICMPMessageTypes<T>,
}

impl ICMPMessage<Vec<u8>> {
    pub fn new_echo_request(identifier: Option<u16>, sequence: u16) -> ICMPMessage<Vec<u8>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();

        let sec = now.as_secs().to_ne_bytes();
        let usec = (now.subsec_micros() as u64).to_ne_bytes();

        let mut data = vec![0u8; 56];
        data[..8].copy_from_slice(&sec);
        data[8..16].copy_from_slice(&usec);

        let padding_start = sec.len() + usec.len();
        for (i, v) in data[padding_start..].iter_mut().enumerate() {
            *v = i as u8;
        }

        ICMPMessage {
            checksum: [0, 0],
            message: ICMPMessageTypes::Echo(EchoMessage {
                identifier: identifier.unwrap_or_else(|| fastrand::u16(..)),
                sequence_number: sequence,
                data,
            }),
        }
    }
}

impl<'a> ICMPMessage<&'a [u8]> {
    pub fn echo_reply(original: &'a EchoMessage<&'a [u8]>) -> Self {
        ICMPMessage {
            checksum: [0, 0],
            message: ICMPMessageTypes::EchoReply(*original),
        }
    }

    pub fn from_bytes(bytes: &'a [u8]) -> std::io::Result<Self> {
        use ICMPMessageTypes::*;

        let code = bytes[1];

        // TODO Compute and validate checksum

        let message = match bytes[0] {
            0 => Ok(EchoReply(bytes.try_into()?)),
            3 => Ok(DestinationUnreachable(DestinationUnreachableMessage {
                code: code.try_into()?,
                data: &bytes[8..],
            })),
            4 => Ok(SourceQuench(&bytes[8..])),
            5 => Ok(Redirect(RedirectMessage {
                code: code.try_into()?,
                gateway: Ipv4Addr::from_octets(
                    bytes[4..8]
                        .try_into()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
                ),
                data: &bytes[8..],
            })),
            8 => Ok(Echo(bytes.try_into()?)),
            11 => Ok(TimeExceeded(TimeExceededMessage {
                code: code.try_into()?,
                data: &bytes[8..],
            })),
            12 => Ok(ParameterProblem(ParameterProblemMessage {
                pointer: bytes[5],
                data: &bytes[8..],
            })),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid ICMP Message",
            )),
        }?;

        Ok(ICMPMessage {
            checksum: [bytes[2], bytes[3]],
            message,
        })
    }
}

impl<T: AsRef<[u8]>> ICMPMessage<T> {
    pub fn len(&self, caller: &str) -> u16 {
        use ICMPMessageTypes::*;

        1 // Type
            + 1 // Code
            + 2 // Checksum
            + match &self.message {
            EchoReply(m) | Echo(m) => {
                2 // Identifier
                    + 2 // Sequence
                    + m.data.as_ref().len() as u16
            }
            DestinationUnreachable(m) => {
                4 // Reserved
                    + m.data.as_ref().len() as u16
            }
            SourceQuench(m) => {
                4 // Reserved
                    + m.as_ref().len() as u16
            }
            // 4=gateway address + data length
            Redirect(m) => {
                4 // Reserved
                    + m.data.as_ref().len() as u16
            }
            // 4=reserved + data length
            TimeExceeded(m) => {
                4 // Reserved
                    + m.data.as_ref().len() as u16
            }
            ParameterProblem(m) => {
                1 // Pointer
                    + 3 // Reserved
                    + m.data.as_ref().len() as u16
            }
        }
    }

    fn type_and_code_u8(&self) -> (u8, u8) {
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

    pub fn write(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        use ICMPMessageTypes::*;

        let mut writer = ChecksummingWriter::new(buffer);

        let (icmp_type, code) = self.type_and_code_u8();

        let mut count = 0;
        count += writer.write(&[icmp_type, code])?;
        let checksum_start = count;
        count += writer.write(&[0, 0])?;

        count += match &self.message {
            Echo(m) | EchoReply(m) => {
                writer.write(&m.identifier.to_be_bytes())?
                    + writer.write(&m.sequence_number.to_be_bytes())?
                    + writer.write(m.data.as_ref())?
            }
            DestinationUnreachable(m) => writer.write(m.data.as_ref())?,
            SourceQuench(data) => writer.write(data.as_ref())?,
            Redirect(m) => writer.write(m.data.as_ref())?,
            TimeExceeded(m) => writer.write(m.data.as_ref())?,
            ParameterProblem(m) => writer.write(m.data.as_ref())?,
        };

        let checksum = writer.checksum();

        buffer[checksum_start] = checksum[0];
        buffer[checksum_start + 1] = checksum[1];

        Ok(count)
    }
}

impl<T: AsRef<[u8]>> Debug for ICMPMessage<T> {
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
                    .field("data", &m.data.as_ref());
            }
            DestinationUnreachable(m) => {
                d.field("data", &m.data.as_ref());
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

        d.field("len()", &(self.len("in debug")));

        d.finish()
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct EchoSequence {
    target: Ipv4Addr,
    current: u16,
    limit: u16,
    last: Option<std::time::Instant>,
    delay: std::time::Duration,
}

#[derive(Debug, Default)]
struct EchoTracker {
    sequences: HashMap<u16, EchoSequence>,
}

impl EchoTracker {
    pub fn ping(&mut self, target: Ipv4Addr, count: u16, delay: std::time::Duration) {
        let identifier = fastrand::u16(..);

        assert!(delay.as_secs() > 1);

        self.sequences.insert(
            identifier,
            EchoSequence {
                target,
                current: 0,
                limit: count,
                last: None,
                delay,
            },
        );
    }

    pub fn send(&mut self, arp: ArpTable, iface: &SyncDevice) {
        todo!()
        // for (identifier, seq) in self.sequences.iter_mut() {
        //    if match seq.last {
        //         Some(last) => last.elapsed() >= seq.delay,
        //         None => true,
        //     } {
        //
        //        let echo = ICMPMessage::new_echo_request(Some(*identifier), seq.current + 1);
        //        let ipv4 =
        //    }
        //
        // }
    }

    pub fn handle(&self, message: ICMPMessage<&[u8]>) {
        todo!()
    }
}
