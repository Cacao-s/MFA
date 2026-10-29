//! A reader for the sliver of protobuf that `otpauth-migration://` uses.
//!
//! Google Authenticator's export is one small, stable message. Decoding it by
//! hand keeps `protoc` out of the build for every platform, which matters more
//! than the hundred lines it costs.

use crate::error::{Error, Result};

/// Protobuf wire types we may encounter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireType {
    Varint,
    Fixed64,
    LengthDelimited,
    Fixed32,
}

impl WireType {
    fn from_tag(bits: u64) -> Result<Self> {
        match bits {
            0 => Ok(WireType::Varint),
            1 => Ok(WireType::Fixed64),
            2 => Ok(WireType::LengthDelimited),
            5 => Ok(WireType::Fixed32),
            // 3 and 4 are the removed group encoding; nothing emits them.
            _ => Err(Error::MalformedProtobuf),
        }
    }
}

/// A cursor over one protobuf message.
#[derive(Debug)]
pub(crate) struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Reads the next field header, or `None` at the end of the message.
    pub(crate) fn next_field(&mut self) -> Result<Option<(u32, WireType)>> {
        if self.is_empty() {
            return Ok(None);
        }
        let tag = self.varint()?;
        let field = u32::try_from(tag >> 3).map_err(|_| Error::MalformedProtobuf)?;
        if field == 0 {
            return Err(Error::MalformedProtobuf);
        }
        Ok(Some((field, WireType::from_tag(tag & 0x07)?)))
    }

    pub(crate) fn varint(&mut self) -> Result<u64> {
        let mut value: u64 = 0;
        for shift in (0..64).step_by(7) {
            let byte = *self.data.get(self.pos).ok_or(Error::MalformedProtobuf)?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f)
                .checked_shl(shift)
                .ok_or(Error::MalformedProtobuf)?;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::MalformedProtobuf)
    }

    /// A length-delimited field's payload.
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = usize::try_from(self.varint()?).map_err(|_| Error::MalformedProtobuf)?;
        let end = self.pos.checked_add(len).ok_or(Error::MalformedProtobuf)?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(Error::MalformedProtobuf)?;
        self.pos = end;
        Ok(slice)
    }

    /// A length-delimited field read as UTF-8, replacing invalid sequences
    /// rather than failing: a mangled account name should not lose the secret
    /// next to it.
    pub(crate) fn string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }

    /// An `int32`/`int64` field. Protobuf stores negatives as 10-byte varints.
    pub(crate) fn int32(&mut self) -> Result<i32> {
        Ok(self.varint()? as i64 as i32)
    }

    /// Steps over a field this build does not care about.
    pub(crate) fn skip(&mut self, wire_type: WireType) -> Result<()> {
        match wire_type {
            WireType::Varint => {
                self.varint()?;
            }
            WireType::Fixed64 => self.advance(8)?,
            WireType::Fixed32 => self.advance(4)?,
            WireType::LengthDelimited => {
                self.bytes()?;
            }
        }
        Ok(())
    }

    fn advance(&mut self, len: usize) -> Result<()> {
        let end = self.pos.checked_add(len).ok_or(Error::MalformedProtobuf)?;
        if end > self.data.len() {
            return Err(Error::MalformedProtobuf);
        }
        self.pos = end;
        Ok(())
    }
}
