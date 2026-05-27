use crate::common::{ChecksummingWriter, WriteToBuffer};
use bitmatch::bitmatch;
use std::fmt::{Debug, Formatter};
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;

/// This is a new-type because the actual representation on the wire is 4-bit int
#[derive(Eq, PartialEq, Copy, Clone)]
pub struct IPv4HeaderLengthWords(u8);

impl IPv4HeaderLengthWords {
    #[bitmatch]
    fn to_byte(self, input: u8) -> u8 {
        let a = input;
        let b = self.0;

        bitpack!("aaaabbbb")
    }

    fn byte_len(self) -> u16 {
        self.0 as u16 * 4
    }
}

impl From<u8> for IPv4HeaderLengthWords {
    fn from(input: u8) -> IPv4HeaderLengthWords {
        IPv4HeaderLengthWords(input & 0x0F)
    }
}

impl Debug for IPv4HeaderLengthWords {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.pad(&format!("{:0}", self.0))
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum TypeOfServicePrecedence {
    NetworkControl,      // 111
    InternetworkControl, // 110
    // In docs as CRITC/ECP
    CriticalAndEmergencyCallProcessing, // 101,
    FlashOverride,                      // 100
    Flash,                              // 011
    Immediate,                          // 010
    Priority,                           // 001
    Routine,                            // 000
}
impl From<u8> for TypeOfServicePrecedence {
    #[bitmatch]
    fn from(input: u8) -> TypeOfServicePrecedence {
        use TypeOfServicePrecedence::*;

        #[bitmatch]
        match input {
            "000?_????" => Routine,
            "001?_????" => Priority,
            "010?_????" => Immediate,
            "011?_????" => Flash,
            "100?_????" => FlashOverride,
            "101?_????" => CriticalAndEmergencyCallProcessing,
            "110?_????" => InternetworkControl,
            "111?_????" => NetworkControl,
        }
    }
}

impl From<TypeOfServicePrecedence> for u8 {
    fn from(input: TypeOfServicePrecedence) -> u8 {
        use TypeOfServicePrecedence::*;
        match input {
            NetworkControl => 0b1110_0000,
            InternetworkControl => 0b1100_0000,
            CriticalAndEmergencyCallProcessing => 0b1010_0000,
            FlashOverride => 0b1000_0000,
            Flash => 0b0110_0000,
            Immediate => 0b0100_0000,
            Priority => 0b0010_0000,
            Routine => 0b0000_0000,
        }
    }
}

/// The Type of Service provides an indication of the abstract
/// parameters of the quality of service desired.  These parameters are
/// to be used to guide the selection of the actual service parameters
/// when transmitting a datagram through a particular network.  Several
/// networks offer service precedence, which somehow treats high
/// precedence traffic as more important than other traffic (generally
/// by accepting only traffic above a certain precedence at time of high
/// load).  The major choice is a three way tradeoff between low-delay,
/// high-reliability, and high-throughput.
///
/// Bits 0-2:  Precedence.
/// Bit    3:  0 = Normal Delay,      1 = Low Delay.
/// Bits   4:  0 = Normal Throughput, 1 = High Throughput.
/// Bits   5:  0 = Normal Relibility, 1 = High Relibility.
/// Bit  6-7:  Reserved for Future Use.
///
/// 0     1     2     3     4     5     6     7
/// +-----+-----+-----+-----+-----+-----+-----+-----+
/// |                 |     |     |     |     |     |
/// |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
/// |                 |     |     |     |     |     |
/// +-----+-----+-----+-----+-----+-----+-----+-----+
///
/// Precedence
///
/// 111 - Network Control
/// 110 - Internetwork Control
/// 101 - CRITIC/ECP
/// 100 - Flash Override
/// 011 - Flash
/// 010 - Immediate
/// 001 - Priority
/// 000 - Routine
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
struct TypeOfService {
    precedence: TypeOfServicePrecedence,
    low_delay: bool,
    high_throughput: bool,
    high_reliability: bool,
}

impl TypeOfService {
    #[bitmatch]
    fn parse_low_delay(input: u8) -> bool {
        #[bitmatch]
        match input {
            "???0_????" => false,
            "???1_????" => true,
        }
    }
    #[bitmatch]
    fn parse_high_throughput(input: u8) -> bool {
        #[bitmatch]
        match input {
            "????_0???" => false,
            "????_1???" => true,
        }
    }
    #[bitmatch]
    fn parse_high_reliability(input: u8) -> bool {
        #[bitmatch]
        match input {
            "????_?0??" => false,
            "????_?1??" => true,
        }
    }

    fn parse(input: u8) -> TypeOfService {
        TypeOfService {
            precedence: input.into(),
            low_delay: Self::parse_low_delay(input),
            high_throughput: Self::parse_high_throughput(input),
            high_reliability: Self::parse_high_reliability(input),
        }
    }

    #[bitmatch]
    fn to_bytes(self) -> [u8; 1] {
        let a: u8 = self.precedence.into();
        let b = self.low_delay;
        let c = self.high_throughput;
        let d = self.high_reliability;

        [bitpack!("aaab_cd00")]
    }
}

/// Flags:  3 bits
///   Various Control Flags.
///   Bit 0: reserved, must be zero
///   Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
///   Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
///     0   1   2
///   +---+---+---+
///   |   | D | M |
///   | 0 | F | F |
///   +---+---+---+
///
/// Fragment Offset:  13 bits
///   This field indicates where in the datagram this fragment belongs.
///   The fragment offset is measured in units of 8 octets (64 bits).  The
///   first fragment has offset zero.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
struct FragmentDetails {
    identification: u16,
    do_not_fragment: bool,
    more_fragments: bool,
    offset: u16,
}

impl FragmentDetails {
    const OFFSET_MAX: u16 = 0x1FFF;

    #[bitmatch]
    fn parse_do_not_fragment(input: u8) -> bool {
        #[bitmatch]
        match input {
            "?0??_????" => false,
            "?1??_????" => true,
        }
    }

    #[bitmatch]
    fn parse_more_fragments(input: u8) -> bool {
        #[bitmatch]
        match input {
            "??0?_????" => false,
            "??1?_????" => true,
        }
    }

    fn parse(input: [u8; 4]) -> FragmentDetails {
        let offset = u16::from_be_bytes(input[2..4].try_into().unwrap()) & Self::OFFSET_MAX;

        FragmentDetails {
            identification: u16::from_be_bytes(input[0..2].try_into().unwrap()),
            do_not_fragment: Self::parse_do_not_fragment(input[2]),
            more_fragments: Self::parse_more_fragments(input[2]),
            offset,
        }
    }

    #[bitmatch]
    fn to_bytes(self) -> [u8; 4] {
        let id = self.identification.to_be_bytes();

        let mut raw = 0u16;
        if self.do_not_fragment {
            raw |= 1 << 14
        }
        if self.more_fragments {
            raw |= 1 << 13
        }
        raw |= self.offset & Self::OFFSET_MAX;
        let packed = raw.to_be_bytes();

        [id[0], id[1], packed[0], packed[1]]
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum IPProtocolTypes {
    ICMP, // 1
    TCP,  // 6,
    UDP,  // 17,
    Other(u8),
}
impl From<u8> for IPProtocolTypes {
    fn from(value: u8) -> Self {
        match value {
            1 => IPProtocolTypes::ICMP,
            6 => IPProtocolTypes::TCP,
            17 => IPProtocolTypes::UDP,
            _ => IPProtocolTypes::Other(value),
        }
    }
}
impl From<IPProtocolTypes> for u8 {
    fn from(value: IPProtocolTypes) -> Self {
        match value {
            IPProtocolTypes::ICMP => 1,
            IPProtocolTypes::TCP => 6,
            IPProtocolTypes::UDP => 17,
            IPProtocolTypes::Other(i) => i,
        }
    }
}

/// Columns adjusted to byte order - docs use base 10
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL  |Type of Service|          Total Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |         Header Checksum       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Options                    |    Padding    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Eq, PartialEq, Copy, Clone)]
pub struct IPv4Header<'a> {
    // const Version = 4
    header_len: IPv4HeaderLengthWords,
    type_of_service: TypeOfService,
    total_length: u16,
    fragment_details: FragmentDetails,
    time_to_live: u8,
    /// Encapsulated protocol eg. ICMP, TCP, UDP etc.
    protocol: IPProtocolTypes,
    header_checksum: u16,
    source_address: Ipv4Addr,
    destination_address: Ipv4Addr,
    options_and_padding: &'a [u8],
}

impl<'a> IPv4Header<'a> {
    pub fn new(
        protocol: IPProtocolTypes,
        source_address: Ipv4Addr,
        destination_address: Ipv4Addr,
        payload_len: u16,
    ) -> Self {
        let header_len = IPv4HeaderLengthWords(5);

        IPv4Header {
            header_len,
            type_of_service: TypeOfService {
                high_reliability: false,
                high_throughput: false,
                low_delay: false,
                precedence: TypeOfServicePrecedence::Routine,
            },
            total_length: header_len.byte_len() + payload_len,
            fragment_details: FragmentDetails {
                do_not_fragment: true,
                identification: fastrand::u16(0..u16::MAX), // TOOD random
                more_fragments: false,
                offset: 0,
            },
            time_to_live: 64,
            protocol,
            header_checksum: 0, // Will compute on write
            source_address,
            destination_address,
            options_and_padding: &[],
        }
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        let version = (bytes[0] & 0xf0) >> 4;
        if version != 4 {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid IPv4 version"));
        }

        // TODO Check header checksum

        let header_len: IPv4HeaderLengthWords = bytes[0].into();
        let header_len_bytes = header_len.byte_len() as usize;
        let options_and_padding: &'a [u8] = &bytes[20..header_len_bytes];

        Ok(IPv4Header {
            header_len,
            type_of_service: TypeOfService::parse(bytes[1]),
            total_length: u16::from_be_bytes(bytes[2..4].try_into().map_err(parse_eol_error)?),
            fragment_details: FragmentDetails::parse(
                bytes[4..8].try_into().map_err(parse_eol_error)?,
            ),
            time_to_live: bytes[8],
            protocol: bytes[9].into(),
            header_checksum: u16::from_be_bytes(bytes[10..12].try_into().map_err(parse_eol_error)?),
            source_address: Ipv4Addr::from_octets(
                bytes[12..16].try_into().map_err(parse_eol_error)?,
            ),
            destination_address: Ipv4Addr::from_octets(
                bytes[16..20].try_into().map_err(parse_eol_error)?,
            ),
            options_and_padding,
        })
    }

    pub fn protocol(&self) -> IPProtocolTypes {
        self.protocol
    }

    pub fn len(&self) -> usize {
        self.header_len.byte_len() as usize
    }

    pub fn source_address(&self) -> Ipv4Addr {
        self.source_address
    }
}

impl<'a> WriteToBuffer for IPv4Header<'a> {
    fn write_to_buffer(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut writer = ChecksummingWriter::new(buffer);

        let mut count = 0;
        count += writer.write(&[self.header_len.to_byte(4u8)])?;
        count += writer.write(&self.type_of_service.to_bytes())?;
        count += writer.write(&self.total_length.to_be_bytes())?;
        count += writer.write(&self.fragment_details.to_bytes())?;
        count += writer.write(&[self.time_to_live, self.protocol.into()])?;
        let checksum_start = count;
        // Checksum needs to be 0 initially, then we compute the checksum, then replace it
        count += writer.write(&[0, 0])?;
        count += writer.write(&self.source_address.octets())?;
        count += writer.write(&self.destination_address.octets())?;

        count += writer.write(self.options_and_padding)?;

        // Compute and update the checksum
        let checksum = writer.checksum();

        buffer[checksum_start] = checksum[0];
        buffer[checksum_start + 1] = checksum[1];

        Ok(count)
    }
}

impl Debug for IPv4Header<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IPv4Header")
            .field("len", &self.header_len)
            .field("type_of_service", &self.type_of_service)
            .field("total_length", &self.total_length)
            .field("fragment_details", &self.fragment_details)
            .field("time_to_live", &self.time_to_live)
            .field("protocol", &self.protocol)
            .field("header_checksum", &self.header_checksum)
            .field("source_address", &self.source_address)
            .field("destination_address", &self.destination_address)
            .field("options_and_padding", &self.options_and_padding)
            .finish()
    }
}

//
// impl Display for IPv4Header {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         writeln!(f, "0               1               2               3");
//         writeln!(f, "0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7");
//         writeln!(f, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
//         writeln!(f, "| 4     | {:0x2}   | {pe of Service|          Total Length         |", );
//         writeln!(f, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
//         writeln!(f, "|         Identification        |Flags|      Fragment Offset    |");
//         writeln!(f, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
//         writeln!(f, "|  Time to Live |    Protocol   |         Header Checksum       |");
//         writeln!(f, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
//         writeln!(f, "|                       Source Address                          |");
//         writeln!(f, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
//         writeln!(f, "|                    Destination Address                        |");
//         writeln!(f, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
//         writeln!(f, "|                    Options                    |    Padding    |");
//         writeln!(f, "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
//
//         Ok(())
//     }
// }
fn parse_eol_error(e: std::array::TryFromSliceError) -> Error {
    Error::new(ErrorKind::UnexpectedEof, e)
}
