use crate::ethernet::{EtherType, EthernetMessage};
use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind};

#[derive(Debug, PartialEq)]
pub enum HardwareType {
    Ethernet,
    Other(u16),
}
impl From<[u8; 2]> for HardwareType {
    fn from(v: [u8; 2]) -> Self {
        match v {
            [0x00, 0x01] => HardwareType::Ethernet,
            _ => HardwareType::Other(u16::from_be_bytes(v.try_into().unwrap())),
        }
    }
}
impl From<HardwareType> for [u8; 2] {
    fn from(value: HardwareType) -> Self {
        use HardwareType::*;

        match value {
            Ethernet => [0x00, 0x01],
            Other(v) => v.to_be_bytes(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ProtocolType {
    IPv4,
    Other(u16),
}

impl From<[u8; 2]> for ProtocolType {
    fn from(v: [u8; 2]) -> Self {
        match v {
            [0x08, 0x00] => ProtocolType::IPv4,
            _ => ProtocolType::Other(u16::from_be_bytes(v)),
        }
    }
}
impl From<ProtocolType> for [u8; 2] {
    fn from(value: ProtocolType) -> Self {
        use ProtocolType::*;
        match value {
            IPv4 => [0x08, 0x00],
            Other(v) => v.to_be_bytes(),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Operation {
    Request,
    Reply,
    Unknown(u16),
}

impl From<[u8; 2]> for Operation {
    fn from(v: [u8; 2]) -> Self {
        match v {
            [0x00, 0x01] => Operation::Request,
            [0x00, 0x02] => Operation::Reply,
            _ => Operation::Unknown(u16::from_be_bytes(v)),
        }
    }
}
impl From<Operation> for [u8; 2] {
    fn from(value: Operation) -> Self {
        use Operation::*;
        match value {
            Request => [0x00, 0x01],
            Reply => [0x00, 0x02],
            Unknown(v) => v.to_be_bytes(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ArpMessage {
    operation: Operation,
    sender_hardware_addr: [u8; 6],
    sender_protocol_addr: [u8; 4],
    target_hardware_addr: [u8; 6],
    target_protocol_addr: [u8; 4],
}

fn parse_eol_error(e: std::array::TryFromSliceError) -> Error {
    Error::new(ErrorKind::UnexpectedEof, e)
}
fn parse_data_error(message: &str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

impl ArpMessage {
    pub fn gratuitous(mac: [u8; 6], ipv4: [u8; 4]) -> Self {
        ArpMessage {
            operation: Operation::Request,
            sender_hardware_addr: mac,
            sender_protocol_addr: ipv4,
            target_hardware_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            target_protocol_addr: ipv4,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
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
        let operation: Operation = operation_raw.into();
        if let Operation::Unknown(op) = operation {
            return Err(parse_data_error(
                format!("Unknown operation {:2x}", op).as_str(),
            ));
        }

        Ok(ArpMessage {
            operation,
            sender_hardware_addr: bytes[8..14].try_into().map_err(parse_eol_error)?,
            sender_protocol_addr: bytes[14..18].try_into().map_err(parse_eol_error)?,
            target_hardware_addr: bytes[18..24].try_into().map_err(parse_eol_error)?,
            target_protocol_addr: bytes[24..28].try_into().map_err(parse_eol_error)?,
        })
    }

    pub fn reply(&self, mac: [u8; 6], ipv4: [u8; 4]) -> ArpMessage {
        ArpMessage {
            operation: Operation::Reply,
            sender_hardware_addr: mac,
            sender_protocol_addr: ipv4,
            target_hardware_addr: self.sender_hardware_addr,
            target_protocol_addr: self.sender_protocol_addr,
        }
    }

    pub fn create_ethernet(&'_ self) -> EthernetMessage<'_> {
        EthernetMessage::new(
            &self.target_hardware_addr,
            &self.sender_hardware_addr,
            EtherType::ARP,
        )
    }

    pub fn write(&self, mut buffer: &mut [u8]) -> Result<usize, Error> {
        use std::io::Write;

        let mut count = 0;

        let hardware_type: [u8; 2] = HardwareType::Ethernet.into();
        count += buffer.write(&hardware_type)?;

        let protocol_type: [u8; 2] = ProtocolType::IPv4.into();
        count += buffer.write(&protocol_type)?;

        // Ethernet and IPv4 addresses fixed length
        count += buffer.write(&[6u8, 4u8])?;

        let operation: [u8; 2] = self.operation.into();
        count += buffer.write(&operation)?;

        count += buffer.write(&self.sender_hardware_addr)?;
        count += buffer.write(&self.sender_protocol_addr)?;
        count += buffer.write(&self.target_hardware_addr)?;
        count += buffer.write(&self.target_protocol_addr)?;

        Ok(count)
    }
}

pub struct ArpTable {
    table: HashMap<[u8; 6], HashSet<[u8; 4]>>,
}

impl ArpTable {
    pub fn new() -> Self {
        ArpTable {
            table: HashMap::new(),
        }
    }

    pub fn handle(
        &mut self,
        recv_ether: EthernetMessage,
        recv_arp: ArpMessage,
        our_mac: [u8; 6],
        our_ip: [u8; 4],
        buffer: &mut [u8],
    ) -> Result<usize, Error> {
        self.table
            .entry(recv_arp.sender_hardware_addr)
            .or_default()
            .insert(recv_arp.sender_protocol_addr);

        let reply_ether = recv_ether.create_reply(&our_mac);
        let reply_arp = recv_arp.reply(our_mac, our_ip);

        let mut count = 0;
        count += reply_ether.write(&mut buffer[..])?;
        count += reply_arp.write(&mut buffer[count..])?;

        Ok(count)
    }
}
