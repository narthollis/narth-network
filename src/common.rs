use internet_checksum::Checksum;

pub struct ChecksummingWriter<'a> {
    checksum: Checksum,
    buffer: &'a mut [u8],
}

impl<'a> ChecksummingWriter<'a> {
    pub fn new(buffer: &'a mut [u8]) -> ChecksummingWriter<'a> {
        ChecksummingWriter {
            checksum: Checksum::new(),
            buffer,
        }
    }

    pub fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        use std::io::Write;
        self.checksum.add_bytes(bytes);
        self.buffer.write(bytes)
    }

    pub fn checksum(&self) -> [u8; 2] {
        self.checksum.checksum()
    }
}
