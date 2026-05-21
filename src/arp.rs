
#[derive(Debug, PartialEq)]
pub enum HardwareType {
    Ethernet,
    Other(u16),
}
impl From<u16> for HardwareType {
    fn from(v: u16) -> Self {
        match v {
            1 => HardwareType::Ethernet,
            _ => HardwareType::Other(v),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ProtocolType {
    IPv4,
    Other(u16),
}

impl From<u16> for ProtocolType {
    fn from(v: u16) -> Self {
        match v {
            0x0800 => ProtocolType::IPv4,
            _ => ProtocolType::Other(v),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Arp<'a> {
    hardware_type: HardwareType,
    protocol_type: ProtocolType,
    hardware_len: u8,
    protocol_len: u8,
    operation: u16,
    sender_hardware_addr: &'a [u8],
    sender_protocol_addr: &'a [u8],
    target_hardware_addr: &'a [u8],
    target_protocol_addr: &'a [u8],
}

impl<'a> Arp<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        let hardware_len = bytes[4];
        let protocol_len = bytes[5];

        let mut pos = 8;
        let sender_hardware_addr = &bytes[pos..pos + hardware_len as usize];

        pos += hardware_len as usize;
        let sender_protocol_addr = &bytes[pos..pos + protocol_len as usize];
        pos += protocol_len as usize;
        let target_hardware_addr = &bytes[pos..pos + hardware_len as usize];
        pos += hardware_len as usize;
        let target_protocol_addr = &bytes[pos..pos + protocol_len as usize];

        Arp {
            hardware_type: u16::from_be_bytes(bytes[0..2].try_into().unwrap()).into(),
            protocol_type: u16::from_be_bytes(bytes[2..4].try_into().unwrap()).into(),
            hardware_len,
            protocol_len,
            operation: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            sender_hardware_addr,
            sender_protocol_addr,
            target_hardware_addr,
            target_protocol_addr,
        }
    }

    //pub fn handle()

    pub fn reply(&self, mac: [u8; 6], ipv4: [u8; 4], mut buffer: &mut [u8]) -> Result<usize, std::io::Error> {
        use std::io::Write;

        let mut size = buffer.write(&1u16.to_be_bytes())?;
        size += buffer.write(&0x0800u16.to_be_bytes())?;
        size += buffer.write(&[6u8])?;
        size += buffer.write(&[4u8])?;
        size += buffer.write(&2u16.to_be_bytes())?;
        size += buffer.write(&mac)?;
        size += buffer.write(&ipv4)?;
        size += buffer.write(self.sender_hardware_addr)?;
        size += buffer.write(self.sender_protocol_addr)?;

        Ok(size)
    }
}