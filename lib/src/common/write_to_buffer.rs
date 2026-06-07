use bytes::{BufMut, Bytes};

pub trait WriteToBuffer {
    fn encoded_length(&self) -> usize;
    fn write_to_buffer<B: BufMut>(&self, buffer: &mut B);
}

impl WriteToBuffer for Bytes {
    fn encoded_length(&self) -> usize {
        self.len()
    }

    fn write_to_buffer<B: BufMut>(&self, buffer: &mut B) {
        buffer.put_slice(self);
    }
}

impl<T: ?Sized + WriteToBuffer> WriteToBuffer for &T {
    fn encoded_length(&self) -> usize {
        (*self).encoded_length()
    }

    fn write_to_buffer<B: BufMut>(&self, buffer: &mut B) {
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

    fn write_to_buffer<Buf: BufMut>(&self, buffer: &mut Buf) {
        self.0.write_to_buffer(buffer);
        self.1.write_to_buffer(buffer);
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

    fn write_to_buffer<Buf: BufMut>(&self, buffer: &mut Buf) {
        self.0.write_to_buffer(buffer);
        self.1.write_to_buffer(buffer);
        self.2.write_to_buffer(buffer);
    }
}
