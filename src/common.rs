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

        let written = self.buffer.write(bytes)?;

        debug_assert_eq!(written, bytes.len());

        Ok(written)
    }

    pub fn checksum(&self) -> [u8; 2] {
        self.checksum.checksum()
    }
}

pub(crate) trait WriteToBuffer {
    fn write_to_buffer(&self, buffer: &mut [u8]) -> std::io::Result<usize>;
}

impl<A, B> WriteToBuffer for (A, B)
where
    A: WriteToBuffer,
    B: WriteToBuffer,
{
    fn write_to_buffer(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        written += self.0.write_to_buffer(&mut buffer[written..])?;
        written += self.1.write_to_buffer(&mut buffer[written..])?;

        Ok(written)
    }
}

impl<A, B, C> WriteToBuffer for (A, B, C)
where
    A: WriteToBuffer,
    B: WriteToBuffer,
    C: WriteToBuffer,
{
    fn write_to_buffer(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        written += self.0.write_to_buffer(&mut buffer[written..])?;
        written += self.1.write_to_buffer(&mut buffer[written..])?;
        written += self.2.write_to_buffer(&mut buffer[written..])?;

        Ok(written)
    }
}

#[inline]
pub(crate) const fn err_as_eof<T>(message: &str) -> impl Fn(T) -> std::io::Error
where
    T: std::error::Error,
{
    move |e| {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("{}: {}", message, e),
        )
    }
}
