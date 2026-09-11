//! CBOR codec helpers with fixed, allocation-free buffers.
//!
//! Encoders write into a caller-provided slice and return the number of bytes
//! used, so the core never needs a global allocator.

use crate::error::CoreError;

/// Maximum size of a serialized configuration record, including its header.
pub const MAX_STORED_CONFIG_LEN: usize = 512;

/// Failure while encoding or decoding CBOR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// The destination buffer was too small or encoding failed.
    Encode,
    /// The input was not valid CBOR for the expected type.
    Decode,
}

impl From<CodecError> for CoreError {
    fn from(_: CodecError) -> Self {
        CoreError::InvalidConfiguration
    }
}

/// A writer over a caller-provided slice that tracks the written length.
pub struct SliceWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> SliceWriter<'a> {
    /// Create a writer over `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// Number of bytes written so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing has been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl minicbor::encode::Write for SliceWriter<'_> {
    type Error = CodecError;

    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let end = self.len.checked_add(data.len()).ok_or(CodecError::Encode)?;
        if end > self.buf.len() {
            return Err(CodecError::Encode);
        }
        self.buf[self.len..end].copy_from_slice(data);
        self.len = end;
        Ok(())
    }
}

/// Encode `value` as CBOR into `buf`; returns the number of bytes written.
pub fn encode_into<T>(value: &T, buf: &mut [u8]) -> Result<usize, CodecError>
where
    T: minicbor::Encode<()>,
{
    let mut writer = SliceWriter::new(buf);
    {
        let mut encoder = minicbor::Encoder::new(&mut writer);
        value
            .encode(&mut encoder, &mut ())
            .map_err(|_| CodecError::Encode)?;
    }
    Ok(writer.len())
}

/// Decode a CBOR value of type `T` from `buf`.
pub fn decode_from<T>(buf: &[u8]) -> Result<T, CodecError>
where
    T: for<'b> minicbor::Decode<'b, ()>,
{
    let mut decoder = minicbor::Decoder::new(buf);
    T::decode(&mut decoder, &mut ()).map_err(|_| CodecError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_small_struct() {
        #[derive(minicbor::Encode, minicbor::Decode, PartialEq, Debug)]
        #[cbor(map)]
        struct Sample {
            #[n(0)]
            a: u16,
            #[n(1)]
            b: bool,
        }

        let value = Sample { a: 0x1234, b: true };
        let mut buf = [0u8; 32];
        let len = encode_into(&value, &mut buf).unwrap();
        assert!(len > 0);
        let back: Sample = decode_from(&buf[..len]).unwrap();
        assert_eq!(value, back);
    }

    #[test]
    fn tiny_buffer_is_rejected() {
        #[derive(minicbor::Encode)]
        struct Big {
            #[n(0)]
            a: [u8; 8],
        }
        let value = Big { a: [0xFF; 8] };
        let mut buf = [0u8; 2];
        assert_eq!(encode_into(&value, &mut buf), Err(CodecError::Encode));
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(decode_from::<u32>(&[0xFF, 0xFF]), Err(CodecError::Decode));
    }
}
