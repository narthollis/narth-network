use bytes::{BufMut, Bytes};

pub trait WriteToBuffer {
    fn encoded_length(&self) -> usize;
    fn write_to_buffer<Buf: BufMut>(&self, buffer: Buf);
}

impl WriteToBuffer for Bytes {
    fn encoded_length(&self) -> usize {
        self.len()
    }

    fn write_to_buffer<Buf: BufMut>(&self, mut buffer: Buf) {
        buffer.put_slice(self);
    }
}

impl<T: ?Sized + WriteToBuffer> WriteToBuffer for &T {
    fn encoded_length(&self) -> usize {
        (*self).encoded_length()
    }

    fn write_to_buffer<Buf: BufMut>(&self, buffer: Buf) {
        (*self).write_to_buffer(buffer);
    }
}

impl<A, B> WriteToBuffer for (A, B)
where
    A: WriteToBuffer,
    B: WriteToBuffer,
{
    fn encoded_length(&self) -> usize {
        self.0.encoded_length() + self.1.encoded_length()
    }

    fn write_to_buffer<Buf: BufMut>(&self, mut buffer: Buf) {
        self.0.write_to_buffer(&mut buffer);
        self.1.write_to_buffer(&mut buffer);
    }
}

impl<A, B, C> WriteToBuffer for (A, B, C)
where
    A: WriteToBuffer,
    B: WriteToBuffer,
    C: WriteToBuffer,
{
    fn encoded_length(&self) -> usize {
        self.0.encoded_length() + self.1.encoded_length() + self.2.encoded_length()
    }

    fn write_to_buffer<Buf: BufMut>(&self, mut buffer: Buf) {
        self.0.write_to_buffer(&mut buffer);
        self.1.write_to_buffer(&mut buffer);
        self.2.write_to_buffer(&mut buffer);
    }
}
