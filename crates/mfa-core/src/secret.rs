//! The shared TOTP secret.
//!
//! [`Secret`] owns its bytes, wipes them on drop, redacts itself in `Debug`,
//! and compares in constant time. It serialises as the unpadded upper-case
//! Base32 string that `otpauth://` URIs and the vault file both use.

use core::fmt;

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// A TOTP shared secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Wraps raw secret bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::EmptySecret);
        }
        Ok(Self(bytes))
    }

    /// Parses a Base32 secret as written by authenticator apps.
    ///
    /// Tolerates what real QR codes contain: lower case, `=` padding, and
    /// spaces or dashes used as grouping in manually typed secrets.
    pub fn from_base32(text: &str) -> Result<Self> {
        let mut normalized: String = text
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .flat_map(char::to_uppercase)
            .collect();

        if normalized.is_empty() {
            return Err(Error::EmptySecret);
        }

        let decoded = BASE32_NOPAD.decode(normalized.as_bytes());
        normalized.zeroize();
        let bytes = decoded.map_err(|_| Error::InvalidSecret)?;

        Self::from_bytes(bytes)
    }

    /// The secret as unpadded upper-case Base32.
    ///
    /// The caller owns the returned `String` and should zeroize it once done.
    pub fn to_base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0)
    }

    /// The raw bytes. Named to make every use site obvious in review.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: an empty secret cannot be constructed.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret(<redacted, {} bytes>)", self.0.len())
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Secret {}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        let mut encoded = self.to_base32();
        let result = serializer.serialize_str(&encoded);
        encoded.zeroize();
        result
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let mut text = String::deserialize(deserializer)?;
        let parsed = Secret::from_base32(&text);
        text.zeroize();
        parsed.map_err(serde::de::Error::custom)
    }
}
