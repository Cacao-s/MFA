//! Byte arrays on the JSON command bus.
//!
//! Base64, not a JSON array of numbers: it is four times smaller, and it is
//! what a C# `byte[]` serialises to by default, so the far side needs no
//! converter of its own. Decoding accepts a number array too, so a
//! hand-written client that sends one still works.
//!
//! This affects only [`crate::capi`]. UniFFI does not go through serde, so the
//! Swift and Kotlin bindings are unaffected.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};

/// For a `Vec<u8>` field.
pub mod required {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_any(BytesVisitor)
    }
}

/// For an `Option<Vec<u8>>` field.
pub mod optional {
    use super::*;

    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_str(&BASE64.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        deserializer.deserialize_option(OptionVisitor)
    }
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a Base64 string or an array of byte values")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        BASE64.decode(value).map_err(E::custom)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(byte) = sequence.next_element::<u16>()? {
            bytes.push(
                u8::try_from(byte)
                    .map_err(|_| A::Error::custom(format!("{byte} is not a byte value")))?,
            );
        }
        Ok(bytes)
    }
}

struct OptionVisitor;

impl<'de> Visitor<'de> for OptionVisitor {
    type Value = Option<Vec<u8>>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("null, a Base64 string, or an array of byte values")
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(BytesVisitor).map(Some)
    }
}

/// A byte array in a result position, so it goes out as Base64 too.
#[derive(Debug, serde::Serialize)]
pub struct Base64Bytes(#[serde(with = "required")] pub Vec<u8>);
