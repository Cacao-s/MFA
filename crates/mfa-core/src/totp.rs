//! HOTP (RFC 4226) and TOTP (RFC 6238) code generation.

use core::fmt;
use core::str::FromStr;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};
use crate::secret::Secret;

/// Digit counts we generate. The spec ships 6 and 8; 7 appears in the wild and
/// costs nothing to support.
pub const MIN_DIGITS: u8 = 6;
pub const MAX_DIGITS: u8 = 8;

/// Default TOTP parameters, used when an `otpauth://` URI omits them.
pub const DEFAULT_PERIOD: u32 = 30;
pub const DEFAULT_DIGITS: u8 = 6;

/// Hash backing the HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Algorithm {
    #[default]
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

impl Algorithm {
    /// The canonical spelling used in `otpauth://` URIs.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        // Issuers write this every which way: "SHA1", "sha1", "SHA-256".
        let normalized: String = text
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(char::to_uppercase)
            .collect();

        match normalized.as_str() {
            "SHA1" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            _ => Err(Error::UnsupportedAlgorithm(text.to_owned())),
        }
    }
}

/// A validated set of TOTP parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpParams {
    #[serde(default)]
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::default(),
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
        }
    }
}

impl TotpParams {
    /// Builds parameters, rejecting values we cannot generate codes for.
    pub fn new(algorithm: Algorithm, digits: u8, period: u32) -> Result<Self> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
            return Err(Error::UnsupportedDigits(digits));
        }
        if period == 0 || period > 3600 {
            return Err(Error::UnsupportedPeriod(period));
        }
        Ok(Self {
            algorithm,
            digits,
            period,
        })
    }

    /// Re-checks a value that arrived through serde or FFI.
    pub fn validate(&self) -> Result<()> {
        Self::new(self.algorithm, self.digits, self.period).map(|_| ())
    }

    /// The period to divide by.
    ///
    /// [`TotpParams`]'s fields are public and `Deserialize` does not run
    /// [`Self::validate`], so a shell can hold a `period` of zero without
    /// having gone through [`Self::new`]. The countdown on the account list
    /// calls into here every second; dividing by zero there would take the
    /// whole app down over a bad field, so clamp instead. Code generation
    /// still refuses the value outright — see [`Self::code_at`].
    fn divisor(&self) -> u64 {
        u64::from(self.period.max(1))
    }

    /// The counter value TOTP uses at `unix_secs` (T0 = 0).
    pub fn counter_at(&self, unix_secs: u64) -> u64 {
        unix_secs / self.divisor()
    }

    /// Seconds until the current code expires, in `1..=period`.
    pub fn remaining_secs_at(&self, unix_secs: u64) -> u32 {
        let period = self.divisor();
        (period - (unix_secs % period)) as u32
    }

    /// Generates the code for the step containing `unix_secs`.
    pub fn code_at(&self, secret: &Secret, unix_secs: u64) -> Result<String> {
        self.validate()?;
        Ok(hotp(
            self.algorithm,
            secret,
            self.counter_at(unix_secs),
            self.digits,
        ))
    }

    /// Generates the code `steps` away from the one containing `unix_secs`.
    ///
    /// Negative `steps` look back, which is what a "check my clock" helper and
    /// a drift-tolerant self-test need.
    pub fn code_at_offset(&self, secret: &Secret, unix_secs: u64, steps: i64) -> Result<String> {
        self.validate()?;
        let counter = self.counter_at(unix_secs).checked_add_signed(steps).ok_or(
            Error::UnsupportedPeriod(self.period), // counter underflow: time before the epoch
        )?;
        Ok(hotp(self.algorithm, secret, counter, self.digits))
    }
}

/// Raw HOTP (RFC 4226 §5.3) with the dynamic-truncation step.
///
/// Crate-internal because it cannot defend itself: `10u32.pow(digits)`
/// overflows above nine digits, and the truncation offset needs a digest of at
/// least 20 bytes. Both hold for every value [`TotpParams`] admits, and
/// [`TotpParams::code_at`] is the only way in.
pub(crate) fn hotp(algorithm: Algorithm, secret: &Secret, counter: u64, digits: u8) -> String {
    debug_assert!(
        (MIN_DIGITS..=MAX_DIGITS).contains(&digits),
        "hotp was handed unvalidated digits"
    );
    let message = counter.to_be_bytes();

    /// HMAC over `message`, returning the digest as bytes.
    macro_rules! digest_with {
        ($hash:ty) => {{
            let mut mac = <Hmac<$hash>>::new_from_slice(secret.expose())
                .expect("HMAC accepts a key of any length");
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }};
    }

    let digest = match algorithm {
        Algorithm::Sha1 => digest_with!(Sha1),
        Algorithm::Sha256 => digest_with!(Sha256),
        Algorithm::Sha512 => digest_with!(Sha512),
    };

    // Dynamic truncation: the low nibble of the last byte picks the window.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);

    let modulus = 10_u32.pow(u32::from(digits));
    format!(
        "{code:0width$}",
        code = binary % modulus,
        width = usize::from(digits)
    )
}
