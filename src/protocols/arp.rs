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

impl From<HardwareType> for u16 {
    fn from(value: HardwareType) -> Self {
        use HardwareType::*;

        match value {
            Ethernet => 0x0001,
            Other(v) => v,
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
impl From<ProtocolType> for u16 {
    fn from(value: ProtocolType) -> Self {
        use ProtocolType::*;
        match value {
            IPv4 => 0x0800,
            Other(v) => v,
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
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
        let operation: Operation = operation_raw.try_into()?;

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
    pub fn source_mac(&self) -> MacAddr {
        self.sender_hardware_addr
    }
    pub fn source_addr(&self) -> Ipv4Addr {
        self.sender_protocol_addr
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
    fn encoded_length(&self) -> usize {
        28
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ArpState {
    /// ARP Request is pending but above timeout, send a new request and let us know
    /// this is also the initial resolve state if no existing entry is found
    PendingRetry,
    /// ARP Request is pending but below timeout, hold your horses
    PendingWait,
    /// If Pending wait time exced and max retry exced
    Timeout,
    /// The entry exists and is current - enjoy
    Resolved(MacAddr),
    /// The entry exists, but it's outside the TTL - so use this but also send a new request please
    ResolvedStale(MacAddr),
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
const ARP_LIFETIME_SEC: u64 = 30;
const ARP_LIFETIME: std::time::Duration = std::time::Duration::from_secs(ARP_LIFETIME_SEC);
const ARP_LIFETIME_STALE_SEC: u64 = 60;

impl ArpTable {
    pub fn update_or_insert(&mut self, mac: MacAddr, ipv4: Ipv4Addr) {
        self.table.insert(
            ipv4,
            ArpTableEntry::Resolved {
                last_seen: Instant::now(),
                address: mac,
            },
        );
    }

    pub fn update_only(&mut self, mac: MacAddr, ipv4: Ipv4Addr) -> bool {
        match self.table.entry(ipv4) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(ArpTableEntry::Resolved {
                    last_seen: Instant::now(),
                    address: mac,
                });
                true
            }
            std::collections::hash_map::Entry::Vacant(_) => false,
        }
    }

    pub fn insert_from_arp(&mut self, arp: &ArpMessage) {
        self.update_or_insert(arp.sender_hardware_addr, arp.sender_protocol_addr);
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
            ArpTableEntry::Resolved { last_seen, address } => match last_seen.elapsed().as_secs() {
                ARP_LIFETIME_STALE_SEC.. => {
                    self.table.remove(&ipv4addr);
                    ArpState::PendingRetry
                }
                ARP_LIFETIME_SEC..ARP_LIFETIME_STALE_SEC => ArpState::ResolvedStale(*address),
                ..ARP_LIFETIME_SEC => ArpState::Resolved(*address),
            },
        }
    }

    pub fn pending(&self) -> Vec<Ipv4Addr> {
        self.table
            .iter()
            .filter(|(_, entry)| matches!(entry, ArpTableEntry::Pending { .. }))
            .map(|(ip, _)| *ip)
            .collect()
    }

    pub fn can_send_request(&mut self, ipv4addr: Ipv4Addr) -> bool {
        let now = Instant::now();
        let entry = self
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
            });
        matches!(entry, ArpTableEntry::Pending { .. })
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
