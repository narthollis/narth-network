use crate::common::err_as_eof;
use crate::protocols::ethernet::mac::{BROADCAST as MAC_BROADCAST, MacAddr};
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use crate::write_to_buffer;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HardwareType {
    Ethernet,
    Other(u16),
}
impl From<[u8; 2]> for HardwareType {
    fn from(v: [u8; 2]) -> Self {
        match v {
            [0x00, 0x01] => Self::Ethernet,
            _ => Self::Other(u16::from_be_bytes(v)),
        }
    }
}

impl From<HardwareType> for u16 {
    fn from(value: HardwareType) -> Self {
        match value {
            HardwareType::Ethernet => 0x0001,
            HardwareType::Other(v) => v,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ProtocolType {
    IPv4,
    Other(u16),
}

impl From<[u8; 2]> for ProtocolType {
    fn from(v: [u8; 2]) -> Self {
        match v {
            [0x08, 0x00] => Self::IPv4,
            _ => Self::Other(u16::from_be_bytes(v)),
        }
    }
}
impl From<ProtocolType> for u16 {
    fn from(value: ProtocolType) -> Self {
        match value {
            ProtocolType::IPv4 => 0x0800,
            ProtocolType::Other(v) => v,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Operation {
    Request,
    Reply,
}

impl TryFrom<[u8; 2]> for Operation {
    type Error = Error;

    fn try_from(v: [u8; 2]) -> Result<Self, Self::Error> {
        match v {
            [0x00, 0x01] => Ok(Operation::Request),
            [0x00, 0x02] => Ok(Operation::Reply),
            _ => Err(Error::new(ErrorKind::InvalidData, "invalid arp operation")),
        }
    }
}
impl From<Operation> for u16 {
    fn from(value: Operation) -> Self {
        use Operation::*;
        match value {
            Request => 0x0001,
            Reply => 0x0002,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct ArpMessage {
    operation: Operation,
    sender_hardware_addr: MacAddr,
    sender_protocol_addr: Ipv4Addr,
    target_hardware_addr: MacAddr,
    target_protocol_addr: Ipv4Addr,
}

fn parse_eol_error(e: std::array::TryFromSliceError) -> Error {
    Error::new(ErrorKind::UnexpectedEof, e)
}
fn parse_data_error(message: &str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

impl ArpMessage {
    const ARP_LENGTH: usize = 28;

    #[must_use]
    pub const fn gratuitous(mac: MacAddr, ipv4: Ipv4Addr) -> Self {
        Self {
            operation: Operation::Request,
            sender_hardware_addr: mac,
            sender_protocol_addr: ipv4,
            target_hardware_addr: MAC_BROADCAST,
            target_protocol_addr: ipv4,
        }
    }

    #[must_use]
    pub const fn request(requester: MacAddr, target_ipv4: Ipv4Addr, sender_ipv4: Ipv4Addr) -> Self {
        Self {
            operation: Operation::Request,
            sender_hardware_addr: requester,
            sender_protocol_addr: sender_ipv4,
            target_hardware_addr: MAC_BROADCAST,
            target_protocol_addr: target_ipv4,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < Self::ARP_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "ARP message too short",
            ));
        }

        let hardware_type_raw: [u8; 2] = bytes[0..2].try_into().map_err(parse_eol_error)?;
        let hardware_type: HardwareType = hardware_type_raw.into();

        let protocol_type_raw: [u8; 2] = bytes[2..4].try_into().map_err(parse_eol_error)?;
        let protocol_type: ProtocolType = protocol_type_raw.into();

        let hardware_len = bytes[4];
        let protocol_len = bytes[5];

        // Validate we have an ARP for IPv4 - we're not worrying about anything else
        // as this is the only modern usage
        if hardware_type != HardwareType::Ethernet {
            return Err(parse_data_error("Unsupported Hardware type"));
        }
        if protocol_type != ProtocolType::IPv4 {
            return Err(parse_data_error("Unsupported Protocol type"));
        }
        if hardware_len != 6 {
            return Err(parse_data_error("Invalid hardware length for Ethernet"));
        }
        if protocol_len != 4 {
            return Err(parse_data_error("Unsupported Protocol length for IPv4"));
        }

        // We only handle Request and Reply
        let operation_raw: [u8; 2] = bytes[6..8].try_into().map_err(parse_eol_error)?;
        let operation: Operation = operation_raw.try_into()?;

        let sender_protocol_addr_raw: [u8; 4] =
            bytes[14..18].try_into().map_err(parse_eol_error)?;
        let sender_protocol_addr = sender_protocol_addr_raw.into();

        let target_protocol_addr_raw: [u8; 4] =
            bytes[24..28].try_into().map_err(parse_eol_error)?;
        let target_protocol_addr = target_protocol_addr_raw.into();

        Ok(Self {
            operation,
            sender_hardware_addr: bytes[8..14]
                .try_into()
                .map_err(err_as_eof("Failed to parse Hardware address"))?,
            sender_protocol_addr,
            target_hardware_addr: bytes[18..24]
                .try_into()
                .map_err(err_as_eof("Failed to parse Protocol address"))?,
            target_protocol_addr,
        })
    }

    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }
    #[must_use]
    pub const fn target_mac(&self) -> MacAddr {
        self.target_hardware_addr
    }
    #[must_use]
    pub const fn target_addr(&self) -> Ipv4Addr {
        self.target_protocol_addr
    }
    #[must_use]
    pub const fn source_mac(&self) -> MacAddr {
        self.sender_hardware_addr
    }
    #[must_use]
    pub const fn source_addr(&self) -> Ipv4Addr {
        self.sender_protocol_addr
    }

    #[must_use]
    pub const fn reply(&self, mac: MacAddr, ipv4: Ipv4Addr) -> ArpMessage {
        ArpMessage {
            operation: Operation::Reply,
            sender_hardware_addr: mac,
            sender_protocol_addr: ipv4,
            target_hardware_addr: self.sender_hardware_addr,
            target_protocol_addr: self.sender_protocol_addr,
        }
    }

    #[must_use]
    pub const fn create_ethernet(&'_ self) -> EthernetHeader {
        EthernetHeader::new(
            EtherType::ARP,
            self.sender_hardware_addr,
            self.target_hardware_addr,
        )
    }
}

impl write_to_buffer::WriteToBuffer for ArpMessage {
    fn encoded_length(&self) -> usize {
        Self::ARP_LENGTH
    }

    fn write_to_buffer<B: bytes::BufMut>(&self, buffer: &mut B) {
        buffer.put_u16(HardwareType::Ethernet.into());
        buffer.put_u16(ProtocolType::IPv4.into());

        // Ethernet and IPv4 addresses fixed length
        buffer.put_u8(0x06);
        buffer.put_u8(0x04);

        buffer.put_u16(self.operation.into());

        buffer.put_slice(&self.sender_hardware_addr.octets());
        buffer.put_slice(&self.sender_protocol_addr.octets());
        buffer.put_slice(&self.target_hardware_addr.octets());
        buffer.put_slice(&self.target_protocol_addr.octets());
    }
}
