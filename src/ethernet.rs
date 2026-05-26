use crate::mac::MacAddr;
use std::fmt::{Debug, Display, Formatter};

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_ARP: u16 = 0x0806;
const ETHER_TYPE_VLAN: u16 = 0x8100;
const ETHER_TYPE_IPV6: u16 = 0x86dd;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum EtherType {
    Ieee8023LengthField(u16),
    IPv4,
    ARP,
    VLAN,
    IPv6,
    Other(u16),
}

impl From<[u8; 2]> for EtherType {
    fn from(val: [u8; 2]) -> EtherType {
        use crate::ethernet::EtherType::*;

        let t = u16::from_be_bytes([val[0], val[1]]);
        match t {
            0..=0x05DC => Ieee8023LengthField(t),
            ETHER_TYPE_IPV4 => IPv4,
            ETHER_TYPE_ARP => ARP,
            ETHER_TYPE_VLAN => VLAN,
            ETHER_TYPE_IPV6 => IPv6,
            _ => Other(t),
        }
    }
}
impl From<&[u8]> for EtherType {
    fn from(value: &[u8]) -> Self {
        [value[0], value[1]].try_into().unwrap()
    }
}

impl From<EtherType> for [u8; 2] {
    fn from(value: EtherType) -> Self {
        match value {
            EtherType::Ieee8023LengthField(v) => v.clone(),
            EtherType::IPv4 => ETHER_TYPE_IPV4,
            EtherType::ARP => ETHER_TYPE_ARP,
            EtherType::VLAN => ETHER_TYPE_VLAN,
            EtherType::IPv6 => ETHER_TYPE_IPV6,
            EtherType::Other(v) => v.clone(),
        }
        .to_be_bytes()
    }
}

impl Display for EtherType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use crate::ethernet::EtherType::*;

        let r = match self {
            Ieee8023LengthField(val) => format!("Len({})", val),
            IPv4 => "IPv4".to_string(),
            ARP => "ARP".to_string(),
            VLAN => "VLAN".to_string(),
            IPv6 => "IPv6".to_string(),
            Other(val) => format!("0x{:04x}", val),
        };

        f.pad(&r)
    }
}

#[derive(PartialEq, Copy, Clone)]
pub struct EthernetMessage<'a> {
    destination_address: MacAddr,
    source_address: MacAddr,
    ether_type: EtherType,
    vlan: Option<u16>,
    payload: &'a [u8],
}

impl<'a> EthernetMessage<'a> {
    pub fn new(destination: MacAddr, source: MacAddr, ether_type: EtherType) -> Self {
        EthernetMessage {
            destination_address: destination,
            source_address: source,
            ether_type,
            vlan: None,
            payload: &[],
        }
    }

    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        let mut ether_type = bytes[12..14].try_into().expect("Can't read protocol");
        let mut vlan = None;
        let mut header_size = 14usize;

        if ether_type == EtherType::VLAN {
            vlan = Some(u16::from_be_bytes(bytes[14..16].try_into().unwrap()));
            ether_type = bytes[16..18].try_into().unwrap();
            header_size = 18;
        }

        EthernetMessage {
            destination_address: bytes[0..6].try_into().unwrap(),
            source_address: bytes[6..12].try_into().unwrap(),
            ether_type,
            vlan,
            payload: &bytes[header_size..],
        }
    }

    pub fn create_reply(&self, our_mac: MacAddr) -> EthernetMessage<'a> {
        let mut reply = self.clone();

        reply.destination_address = reply.source_address;
        reply.source_address = our_mac;

        reply
    }

    pub fn write(&self, mut buffer: &mut [u8]) -> Result<usize, std::io::Error> {
        use std::io::Write;

        let mut count = buffer.write(&self.destination_address.octets())?;
        count += buffer.write(&self.source_address.octets())?;
        if let Some(vlan) = self.vlan {
            count += buffer.write(&ETHER_TYPE_VLAN.to_be_bytes())?;
            count += buffer.write(&vlan.to_be_bytes())?;
        }
        let ether_type: [u8; 2] = self.ether_type.into();
        count += buffer.write(&ether_type)?;
        Ok(count)
    }

    pub fn destination_address(&self) -> MacAddr {
        self.destination_address
    }
    pub fn source_address(&self) -> MacAddr {
        self.source_address
    }
    pub fn ether_type(&self) -> EtherType {
        self.ether_type
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl Debug for EthernetMessage<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthernetMessage")
            .field("destination_address", &self.destination_address)
            .field("source_address", &self.source_address)
            .field("ether_type", &self.ether_type)
            .field("vlan", &self.vlan)
            .field("payload", &format_args!("len({})", self.payload.len()))
            .finish()
    }
}
