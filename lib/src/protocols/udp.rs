use crate::protocols::ipv4::IPProtocolTypes;
use crate::write_to_buffer::WriteToBuffer;
use std::net::Ipv4Addr;

#[derive(Debug, Copy, Clone)]
pub struct UdpHeader {
    source_port: u16,
    destination_port: u16,
    length: u16,
    pub(crate) checksum: [u8; 2],
}

impl UdpHeader {
    pub const LENGTH: usize = 8;

    #[must_use]
    pub const fn new(source_port: u16, destination_port: u16, payload_length: u16) -> Self {
        Self {
            source_port,
            destination_port,
            length: payload_length + Self::LENGTH as u16,
            checksum: [0u8; 2],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> std::io::Result<Self> {
        if bytes.len() < Self::LENGTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Invalid length for UDP header",
            ));
        }

        Ok(Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            length: u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: [bytes[6], bytes[7]],
        })
    }

    #[must_use]
    pub fn compute_checksum_v4(
        &self,
        source_addr: &Ipv4Addr,
        destination_addr: &Ipv4Addr,
        data: &[u8],
    ) -> [u8; 2] {
        let mut checksum = internet_checksum::Checksum::new();
        // construct the pseudo-header
        checksum.add_bytes(source_addr.octets().as_ref());
        checksum.add_bytes(destination_addr.octets().as_ref());
        checksum.add_bytes(&[0x00, IPProtocolTypes::UDP.into()]); // 0u8 is an unused/reserved byte
        checksum.add_bytes(self.length.to_be_bytes().as_ref());
        checksum.add_bytes(self.source_port.to_be_bytes().as_ref());
        checksum.add_bytes(self.destination_port.to_be_bytes().as_ref());
        checksum.add_bytes(self.length.to_be_bytes().as_ref());
        checksum.add_bytes(&[0x00, 0x00]); // checksum placeholder
        checksum.add_bytes(data[..self.length as usize - Self::LENGTH].as_ref());

        let checksum = checksum.checksum();
        // RFC 768: If the computed checksum is 0, it is transmitted as all ones.
        if checksum == [0x00, 0x00] {
            [0xFF, 0xFF]
        } else {
            checksum
        }
    }

    #[must_use]
    pub fn validate_checksum_v4(
        &self,
        source_addr: &Ipv4Addr,
        destination_addr: &Ipv4Addr,
        data: &[u8],
    ) -> bool {
        self.compute_checksum_v4(source_addr, destination_addr, data) == self.checksum
    }

    pub fn compute_and_update_checksum_v4(
        &mut self,
        source_addr: &Ipv4Addr,
        destination_addr: &Ipv4Addr,
        data: &[u8],
    ) {
        self.checksum = self.compute_checksum_v4(source_addr, destination_addr, data);
    }

    #[must_use]
    pub const fn datagram_length(&self) -> usize {
        self.length as usize
    }

    #[must_use]
    pub const fn destination_port(&self) -> u16 {
        self.destination_port
    }

    #[must_use]
    pub const fn source_port(&self) -> u16 {
        self.source_port
    }
}

impl WriteToBuffer for UdpHeader {
    fn encoded_length(&self) -> usize {
        Self::LENGTH
    }

    fn write_to_buffer<Buf: bytes::BufMut>(&self, mut buffer: Buf) {
        buffer.put_u16(self.source_port);
        buffer.put_u16(self.destination_port);
        buffer.put_u16(self.length);
        buffer.put_slice(self.checksum.as_ref());
    }
}
