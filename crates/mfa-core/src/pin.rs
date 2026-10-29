//! The fallback PIN for the app lock.
//!
//! A 4-to-8 digit PIN has very little entropy, so Argon2id here is not what
//! keeps an attacker out: the vault's data key lives in the platform secure
//! store, behind the OS's own rate limiting and biometric gate. This verifier
//! exists so that a PIN entered in the app can be checked without the PIN
//! itself ever being stored, and so that an attacker who reads the vault file
//! does not get an instantly brute-forceable hash either.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::crypto::{self, KdfParams};
use crate::error::{Error, Result};

/// Shortest PIN we let a user set.
pub const MIN_PIN_LEN: usize = 4;

/// A stored PIN verifier: parameters, salt and hash, never the PIN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinVerifier {
    kdf: KdfParams,
    /// Base64.
    salt: String,
    /// Base64.
    hash: String,
}

impl PinVerifier {
    /// Derives a verifier for `pin`.
    pub fn new(pin: &str, kdf: &KdfParams) -> Result<Self> {
        if pin.chars().count() < MIN_PIN_LEN {
            return Err(Error::InvalidParameter(
                format!("shorter than {MIN_PIN_LEN} characters"),
                "pin",
            ));
        }

        let salt = crypto::random_salt();
        let key = crypto::derive_key(pin.as_bytes(), &salt, kdf)?;
        Ok(Self {
            kdf: *kdf,
            salt: BASE64.encode(salt),
            hash: BASE64.encode(key.expose()),
        })
    }

    /// Checks `pin` in constant time.
    pub fn verify(&self, pin: &str) -> bool {
        let Ok(salt) = BASE64.decode(&self.salt) else {
            return false;
        };
        let Ok(mut expected) = BASE64.decode(&self.hash) else {
            return false;
        };
        let Ok(derived) = crypto::derive_key(pin.as_bytes(), &salt, &self.kdf) else {
            expected.zeroize();
            return false;
        };

        let matches = derived.expose().as_slice().ct_eq(&expected).into();
        expected.zeroize();
        matches
    }
}
