use crate::common;
use crate::common::err_as_eof;
use crate::protocols::ethernet::mac::{BROADCAST as MAC_BROADCAST, MacAddr};
use crate::protocols::ethernet::{EtherType, EthernetHeader};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use std::time::Instant;

#[derive(Debug, PartialEq)]
pub enum HardwareType {
    Ethernet,
    Other(u16),
}
impl From<[u8; 2]> for HardwareType {
    fn from(v: [u8; 2]) -> Self {
        match v {
            [0x00, 0x01] => HardwareType::Ethernet,
            _ => HardwareType::Other(u16::from_be_bytes(v)),
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
    pub fn gratuitous(mac: MacAddr, ipv4: Ipv4Addr) -> Self {
        ArpMessage {
            operation: Operation::Request,
            sender_hardware_addr: mac,
            sender_protocol_addr: ipv4,
            target_hardware_addr: MAC_BROADCAST,
            target_protocol_addr: ipv4,
        }
    }

    pub fn request(requester: MacAddr, ipv4: Ipv4Addr) -> Self {
        ArpMessage {
            operation: Operation::Request,
            sender_hardware_addr: requester,
            sender_protocol_addr: Ipv4Addr::new(0, 0, 0, 0),
            target_hardware_addr: MAC_BROADCAST,
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

        let sender_protocol_addr_raw: [u8; 4] =
            bytes[14..18].try_into().map_err(parse_eol_error)?;
        let sender_protocol_addr = sender_protocol_addr_raw.into();

        let target_protocol_addr_raw: [u8; 4] =
            bytes[24..28].try_into().map_err(parse_eol_error)?;
        let target_protocol_addr = target_protocol_addr_raw.into();

        Ok(ArpMessage {
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

    pub fn operation(&self) -> Operation {
        self.operation
    }
    pub fn target_mac(&self) -> MacAddr {
        self.target_hardware_addr
    }
    pub fn target_addr(&self) -> Ipv4Addr {
        self.target_protocol_addr
    }
    pub fn len(&self) -> usize {
        28
    }

    pub fn reply(&self, mac: MacAddr, ipv4: Ipv4Addr) -> ArpMessage {
        ArpMessage {
            operation: Operation::Reply,
            sender_hardware_addr: mac,
            sender_protocol_addr: ipv4,
            target_hardware_addr: self.sender_hardware_addr,
            target_protocol_addr: self.sender_protocol_addr,
        }
    }

    pub fn create_ethernet(&'_ self) -> EthernetHeader {
        EthernetHeader::new(
            EtherType::ARP,
            self.sender_hardware_addr,
            self.target_hardware_addr,
        )
    }
}

impl common::WriteToBuffer for ArpMessage {
    fn write_to_buffer(&self, mut buffer: &mut [u8]) -> Result<usize, Error> {
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

        count += buffer.write(&self.sender_hardware_addr.octets())?;
        count += buffer.write(&self.sender_protocol_addr.octets())?;
        count += buffer.write(&self.target_hardware_addr.octets())?;
        count += buffer.write(&self.target_protocol_addr.octets())?;

        Ok(count)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ArpState {
    /// ARP Request is pending but above timeout, send a new request and let us know
    /// this is also the initial resolve state if no existing entry is found
    PendingRetry,
    /// ARP Request is pending but below timeout, hold your horses
    PendingWait,
    /// If Pending wait time exced and max retry exced
    Timeout,
    Resolved(MacAddr),
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum ArpTableEntry {
    Pending {
        since: Instant,
        retry_count: u8,
    },
    Resolved {
        last_seen: Instant,
        address: MacAddr,
    },
    // Shares a TTL with Resolved
    Timeout {
        since: Instant,
    },
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct ArpTable {
    table: HashMap<Ipv4Addr, ArpTableEntry>,
}

const ARP_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
const ARP_REQUEST_MAX_RETRY: u8 = 5;
const ARP_LIFETIME: std::time::Duration = std::time::Duration::from_secs(30);

impl ArpTable {
    pub fn new() -> Self {
        ArpTable {
            table: HashMap::new(),
        }
    }

    pub fn update(&mut self, mac: MacAddr, ipv4: Ipv4Addr) {
        self.table.insert(
            ipv4,
            ArpTableEntry::Resolved {
                last_seen: Instant::now(),
                address: mac,
            },
        );
    }

    pub fn update_from_arp(&mut self, arp: ArpMessage) {
        self.update(arp.sender_hardware_addr, arp.sender_protocol_addr);
    }

    pub fn request(&mut self, ipv4addr: Ipv4Addr) -> ArpState {
        match self
            .table
            .entry(ipv4addr)
            .or_insert(ArpTableEntry::Pending {
                since: Instant::now(),
                retry_count: 0,
            }) {
            ArpTableEntry::Pending { retry_count, since } => {
                if since.elapsed() > ARP_REQUEST_TIMEOUT {
                    if *retry_count >= ARP_REQUEST_MAX_RETRY {
                        self.table.insert(
                            ipv4addr,
                            ArpTableEntry::Timeout {
                                since: Instant::now(),
                            },
                        );

                        ArpState::Timeout
                    } else {
                        ArpState::PendingRetry
                    }
                } else {
                    ArpState::PendingWait
                }
            }
            ArpTableEntry::Timeout { since } => {
                if since.elapsed() > ARP_LIFETIME {
                    self.table.remove(&ipv4addr);
                    ArpState::PendingRetry
                } else {
                    ArpState::Timeout
                }
            }
            ArpTableEntry::Resolved { last_seen, address } => {
                if last_seen.elapsed() > ARP_LIFETIME {
                    self.table.remove(&ipv4addr);
                    ArpState::PendingRetry
                } else {
                    ArpState::Resolved(*address)
                }
            }
        }
    }

    pub fn can_send_request(&mut self, ipv4addr: Ipv4Addr) -> bool {
        let now = Instant::now();
        match self
            .table
            .entry(ipv4addr)
            .and_modify(|mut entry| {
                if let ArpTableEntry::Pending { retry_count, since } = &mut entry {
                    *retry_count += 1;
                    *since = now;
                }
            })
            .or_insert(ArpTableEntry::Pending {
                since: now,
                retry_count: 0,
            }) {
            ArpTableEntry::Pending { .. } => true,
            _ => false,
        }
    }

    // pub fn handle(&mut self, recv_arp: ArpMessage, our_mac: MacAddr) -> Result<ArpMessage, Error> {
    //     self.table
    //         .entry(recv_arp.sender_hardware_addr)
    //         .or_default()
    //         .insert(recv_arp.sender_protocol_addr);
    //
    //     Ok(recv_arp.reply(our_mac, recv_arp.target_protocol_addr))
    // }

    // let mut count = 0;
    //     count += reply_ether.write(&mut buffer[..])?;
    //     count += reply_arp.write(&mut buffer[count..])?;

    // let r = EthernetMessage::from_bytes(&buffer[..count]);
    // let ra = ArpMessage::from_bytes(r.payload()).unwrap();

    // println!("< {:?}", r);
    // println!("< {:?}", ra);

    //     Ok(count)
    // }
}
