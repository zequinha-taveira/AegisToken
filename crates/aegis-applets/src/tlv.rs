//! Minimal BER-TLV reader and writer for the applet protocols.
//!
//! Applets (PIV, OpenPGP, OATH) exchange BER-TLV structures: a tag of one to
//! three bytes, a definite length of one to four bytes, and a value. The reader
//! borrows the frame it parses; the writer helpers encode into a caller buffer
//! and never allocate.

/// A parsed TLV element borrowing its value from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    /// Tag, as an unsigned integer (multi-byte tags are combined).
    pub tag: u32,
    /// Value bytes.
    pub value: &'a [u8],
}

/// Iterator over the consecutive TLVs of a value field.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Start reading TLVs from `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// Whether all input has been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Tlv<'a>;

    /// Parse the next TLV, or `None` when the input is malformed or exhausted.
    fn next(&mut self) -> Option<Tlv<'a>> {
        let (tag, tag_len) = read_tag(self.rest)?;
        let (length, length_len) = read_length(&self.rest[tag_len..])?;
        let header = tag_len + length_len;
        let value = self.rest.get(header..header + length)?;
        self.rest = &self.rest[header + length..];
        Some(Tlv { tag, value })
    }
}

/// Find the first TLV with `tag` in a value field.
#[must_use]
pub fn find(bytes: &[u8], tag: u32) -> Option<&[u8]> {
    Reader::new(bytes)
        .find(|tlv| tlv.tag == tag)
        .map(|tlv| tlv.value)
}

/// Parse a tag, returning it and its encoded length.
///
/// Tags are one byte when the low five bits are not all set, otherwise they
/// continue until a byte without the high bit; at most three bytes are accepted
/// (enough for the 24-bit object identifiers used by PIV).
#[must_use]
pub fn read_tag(bytes: &[u8]) -> Option<(u32, usize)> {
    let first = *bytes.first()?;
    if first & 0x1F != 0x1F {
        return Some((u32::from(first), 1));
    }
    let mut tag = u32::from(first);
    for (index, byte) in bytes.iter().enumerate().skip(1) {
        if index > 3 {
            return None;
        }
        tag = (tag << 8) | u32::from(*byte);
        if byte & 0x80 == 0 {
            return Some((tag, index + 1));
        }
    }
    None
}

/// Parse a definite length, returning it and its encoded length.
///
/// Indefinite lengths (`0x80`) are rejected.
#[must_use]
pub fn read_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7F);
    if count == 0 || count > 3 || bytes.len() < 1 + count {
        return None;
    }
    let mut length = 0usize;
    for byte in &bytes[1..1 + count] {
        length = (length << 8) | usize::from(*byte);
    }
    Some((length, 1 + count))
}

/// Write `tag || length || value` into `out`, returning the encoded length.
pub fn write(tag: u32, value: &[u8], out: &mut [u8]) -> Option<usize> {
    let header = write_header(tag, value.len(), out)?;
    let end = header + value.len();
    out.get_mut(header..end)?.copy_from_slice(value);
    Some(end)
}

/// Write `tag || length` for a value of `len` bytes, returning the header size.
pub fn write_header(tag: u32, len: usize, out: &mut [u8]) -> Option<usize> {
    let tag_len = write_tag(tag, out)?;
    let length_len = write_length(len, out.get_mut(tag_len..)?)?;
    Some(tag_len + length_len)
}

/// Number of bytes [`write`] needs for a value of `len` bytes.
#[must_use]
pub const fn encoded_len(tag: u32, len: usize) -> usize {
    tag_encoded_len(tag) + length_encoded_len(len) + len
}

const fn tag_encoded_len(tag: u32) -> usize {
    if tag <= 0xFF {
        1
    } else if tag <= 0xFFFF {
        2
    } else {
        3
    }
}

const fn length_encoded_len(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len <= 0xFF {
        2
    } else if len <= 0xFFFF {
        3
    } else {
        4
    }
}

fn write_tag(tag: u32, out: &mut [u8]) -> Option<usize> {
    let len = tag_encoded_len(tag);
    if out.len() < len {
        return None;
    }
    for (index, byte) in out.iter_mut().take(len).enumerate() {
        *byte = ((tag >> (8 * (len - 1 - index))) & 0xFF) as u8;
    }
    Some(len)
}

fn write_length(len: usize, out: &mut [u8]) -> Option<usize> {
    let needed = length_encoded_len(len);
    if out.len() < needed {
        return None;
    }
    match needed {
        1 => out[0] = len as u8,
        2 => {
            out[0] = 0x81;
            out[1] = len as u8;
        }
        3 => {
            out[0] = 0x82;
            out[1..3].copy_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out[0] = 0x83;
            let bytes = (len as u32).to_be_bytes();
            out[1..4].copy_from_slice(&bytes[1..]);
        }
    }
    Some(needed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_single_byte_tags() {
        let mut reader = Reader::new(&[0x80, 0x01, 0xAA, 0x53, 0x00]);
        assert_eq!(
            reader.next(),
            Some(Tlv {
                tag: 0x80,
                value: &[0xAA]
            })
        );
        assert_eq!(
            reader.next(),
            Some(Tlv {
                tag: 0x53,
                value: &[]
            })
        );
        assert!(reader.is_empty());
        assert_eq!(reader.next(), None);
    }

    #[test]
    fn reads_multi_byte_object_identifiers() {
        // `5C 03 5F C1 05` carries the PIV object identifier 0x5FC105.
        let mut reader = Reader::new(&[0x5C, 0x03, 0x5F, 0xC1, 0x05]);
        let tlv = reader.next().unwrap();
        assert_eq!(tlv.tag, 0x5C);
        assert_eq!(read_tag(tlv.value), Some((0x5FC105, 3)));
    }

    #[test]
    fn reads_long_lengths() {
        let mut bytes = [0u8; 40];
        bytes[0] = 0x86;
        bytes[1] = 0x81;
        bytes[2] = 0x25;
        let mut reader = Reader::new(&bytes);
        let tlv = reader.next().unwrap();
        assert_eq!(tlv.tag, 0x86);
        assert_eq!(tlv.value.len(), 0x25);

        let mut long = vec![0u8; 300];
        long[0] = 0x70;
        long[1] = 0x82;
        long[2] = 0x01;
        long[3] = 0x28;
        let mut reader = Reader::new(&long);
        let tlv = reader.next().unwrap();
        assert_eq!(tlv.tag, 0x70);
        assert_eq!(tlv.value.len(), 296);
    }

    #[test]
    fn rejects_malformed_input() {
        // Indefinite length.
        assert_eq!(Reader::new(&[0x70, 0x80]).next(), None);
        // Truncated value.
        assert_eq!(Reader::new(&[0x80, 0x05, 0xAA]).next(), None);
        // Truncated multi-byte tag.
        assert_eq!(Reader::new(&[0x5F, 0xC1]).next(), None);
        // Unsupported length form.
        assert_eq!(Reader::new(&[0x80, 0x84, 0, 0, 0, 1]).next(), None);
    }

    #[test]
    fn find_locates_nested_tags() {
        let bytes = [0x7C, 0x05, 0x82, 0x00, 0x81, 0x01, 0xAA];
        let template = find(&bytes, 0x7C).unwrap();
        assert_eq!(find(template, 0x81), Some(&[0xAA][..]));
        assert_eq!(find(template, 0x82), Some(&[][..]));
        assert_eq!(find(template, 0x80), None);
    }

    #[test]
    fn writes_tags_and_lengths() {
        let mut out = [0u8; 16];
        let len = write(0x86, &[0x04, 0x01, 0x02], &mut out).unwrap();
        assert_eq!(&out[..len], &[0x86, 0x03, 0x04, 0x01, 0x02]);

        let mut out = [0u8; 8];
        let len = write(0x5FC105, &[], &mut out).unwrap();
        assert_eq!(&out[..len], &[0x5F, 0xC1, 0x05, 0x00]);
    }

    #[test]
    fn writes_long_lengths() {
        let value = [0xAAu8; 300];
        let mut out = [0u8; 320];
        let len = write(0x70, &value, &mut out).unwrap();
        assert_eq!(len, 4 + 300);
        assert_eq!(&out[..4], &[0x70, 0x82, 0x01, 0x2C]);
    }

    #[test]
    fn encoded_len_matches_written_size() {
        for (tag, len) in [(0x80u32, 0usize), (0x86, 127), (0x5FC105, 128), (0x70, 300)] {
            let mut out = [0u8; 512];
            assert_eq!(
                write_header(tag, len, &mut out),
                Some(encoded_len(tag, len) - len)
            );
        }
    }

    #[test]
    fn writer_rejects_small_buffers() {
        let mut out = [0u8; 2];
        assert_eq!(write(0x86, &[1, 2], &mut out), None);
    }
}
