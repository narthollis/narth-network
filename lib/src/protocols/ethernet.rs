pub mod mac;

use crate::common::{WriteToBuffer, err_as_eof};
use mac::MacAddr;
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
        use EtherType::*;

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
impl TryFrom<&[u8]> for EtherType {
    type Error = std::io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let v: [u8; 2] = value
            .try_into()
            .map_err(err_as_eof("failed to decode EtherType"))?;

        Ok(v.into())
    }
}

impl From<EtherType> for u16 {
    fn from(value: EtherType) -> Self {
        match value {
            EtherType::Ieee8023LengthField(v) => v.clone(),
            EtherType::IPv4 => ETHER_TYPE_IPV4,
            EtherType::ARP => ETHER_TYPE_ARP,
            EtherType::VLAN => ETHER_TYPE_VLAN,
            EtherType::IPv6 => ETHER_TYPE_IPV6,
            EtherType::Other(v) => v.clone(),
        }
    }
}

impl Display for EtherType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use EtherType::*;

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

#[derive(PartialEq, Clone, Copy)]
pub struct EthernetHeader {
    destination_address: MacAddr,
    source_address: MacAddr,
    ether_type: EtherType,
    vlan: Option<u16>,
}

impl EthernetHeader {
    pub const MIN_LENGTH: usize = 14;
    pub const MAX_LENGTH: usize = 18;

    #[must_use]
    pub const fn new(ether_type: EtherType, source: MacAddr, destination: MacAddr) -> Self {
        Self {
            destination_address: destination,
            source_address: source,
            ether_type,
            vlan: None,
        }
    }

    pub fn from_bytes(bytes: &bytes::Bytes) -> std::io::Result<Self> {
        if bytes.len() < Self::MIN_LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "ethernet header too short",
            ));
        }

        let mut ether_type = bytes[12..14].try_into()?;
        let mut vlan = None;

        if ether_type == EtherType::VLAN {
            vlan = Some(u16::from_be_bytes(
                bytes[14..16]
                    .try_into()
                    .map_err(err_as_eof("failed to parse vlan"))?,
            ));
            ether_type = bytes[16..18].try_into()?;
        }

        Ok(EthernetHeader {
            destination_address: bytes[0..6]
                .try_into()
                .map_err(err_as_eof("failed to parse destination"))?,
            source_address: bytes[6..12]
                .try_into()
                .map_err(err_as_eof("failed to parse source"))?,
            ether_type,
            vlan,
        })
    }

    #[must_use]
    pub const fn destination_address(&self) -> MacAddr {
        self.destination_address
    }
    #[must_use]
    pub const fn source_address(&self) -> MacAddr {
        self.source_address
    }
    #[must_use]
    pub const fn ether_type(&self) -> EtherType {
        self.ether_type
    }
}

impl WriteToBuffer for EthernetHeader {
    fn encoded_length(&self) -> usize {
        match self.vlan {
            None => 14,
            Some(_) => 18,
        }
    }

    fn write_to_buffer<B: bytes::BufMut>(&self, buffer: &mut B) {
        buffer.put_slice(&self.destination_address.octets());
        buffer.put_slice(&self.source_address.octets());

        if let Some(vlan) = self.vlan {
            buffer.put_u16(ETHER_TYPE_VLAN);
            buffer.put_u16(vlan);
        }

        buffer.put_u16(self.ether_type.into());
    }
}

impl Debug for EthernetHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthernetHeader")
            .field("destination_address", &self.destination_address)
            .field("source_address", &self.source_address)
            .field("ether_type", &self.ether_type)
            .field("vlan", &self.vlan)
            .finish()
    }
}
