//! Importing Google Authenticator exports (`otpauth-migration://offline?data=…`).
//!
//! A large export is split over several QR codes. [`MigrationCollector`] holds
//! the batches as they are scanned and only yields accounts once the set is
//! complete, so a partial import can never look like a finished one.

use std::collections::BTreeMap;

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;

use crate::error::{Error, Result};
use crate::protobuf::{Decoder, WireType};
use crate::secret::Secret;
use crate::totp::{Algorithm, TotpParams, DEFAULT_PERIOD};
use crate::uri::{strip_scheme, OtpauthUri};

/// Exporters disagree about padding and about `+` versus `-`; accept all four
/// combinations rather than reject a QR code the user cannot re-export.
const BASE64_CONFIG: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
const BASE64_STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, BASE64_CONFIG);
const BASE64_URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, BASE64_CONFIG);

/// Why an entry in the export did not become an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// HOTP is out of scope for v1 (spec §1).
    CounterBased,
    /// Google Authenticator can store MD5; we will not generate those codes.
    UnsupportedAlgorithm(String),
    /// The entry had no usable secret.
    MalformedSecret,
}

impl core::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SkipReason::CounterBased => {
                f.write_str("counter-based (HOTP) accounts are not supported")
            }
            SkipReason::UnsupportedAlgorithm(name) => write!(f, "unsupported algorithm {name}"),
            SkipReason::MalformedSecret => f.write_str("the secret was missing or malformed"),
        }
    }
}

/// An entry we could not import, so the UI can name it instead of silently
/// dropping it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedAccount {
    pub display_name: String,
    pub reason: SkipReason,
}

/// One scanned migration QR code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationBatch {
    pub version: i32,
    /// How many QR codes the export was split into. `0` means "not stated",
    /// which Google Authenticator does for a single-code export.
    pub batch_size: i32,
    pub batch_index: i32,
    /// Identifies the export run; all codes of one export share it.
    pub batch_id: i32,
    pub accounts: Vec<OtpauthUri>,
    pub skipped: Vec<SkippedAccount>,
}

impl MigrationBatch {
    /// Number of QR codes in this export, with `batch_size: 0` normalised.
    pub fn expected_batches(&self) -> usize {
        self.batch_size.max(1) as usize
    }
}

/// Parses one `otpauth-migration://` URI.
pub fn parse_migration_uri(uri: &str) -> Result<MigrationBatch> {
    let rest = strip_scheme(uri, "otpauth-migration").ok_or(Error::NotMigrationUri)?;
    let query = rest.split_once('?').map(|(_, query)| query).unwrap_or("");

    let data = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| key.eq_ignore_ascii_case("data"))
        .map(|(_, value)| value)
        .ok_or(Error::NotMigrationUri)?;

    parse_migration_payload(&decode_data(data)?)
}

/// Decodes the `data` parameter: percent-decoding, then Base64.
fn decode_data(value: &str) -> Result<Vec<u8>> {
    let percent_decoded = percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| Error::InvalidPercentEncoding)?;
    // A literal `+` in a query string means `+` here: the payload is Base64,
    // never form-encoded.
    let trimmed = percent_decoded.trim();

    BASE64_STANDARD
        .decode(trimmed)
        .or_else(|_| BASE64_URL_SAFE.decode(trimmed))
        .map_err(|_| Error::MalformedMigrationData)
}

/// Parses a decoded `MigrationPayload` protobuf message.
pub fn parse_migration_payload(payload: &[u8]) -> Result<MigrationBatch> {
    let mut batch = MigrationBatch {
        version: 0,
        batch_size: 0,
        batch_index: 0,
        batch_id: 0,
        accounts: Vec::new(),
        skipped: Vec::new(),
    };

    let mut decoder = Decoder::new(payload);
    while let Some((field, wire_type)) = decoder.next_field()? {
        match (field, wire_type) {
            (1, WireType::LengthDelimited) => match parse_otp_parameters(decoder.bytes()?)? {
                Ok(account) => batch.accounts.push(account),
                Err(skipped) => batch.skipped.push(skipped),
            },
            (2, WireType::Varint) => batch.version = decoder.int32()?,
            (3, WireType::Varint) => batch.batch_size = decoder.int32()?,
            (4, WireType::Varint) => batch.batch_index = decoder.int32()?,
            (5, WireType::Varint) => batch.batch_id = decoder.int32()?,
            _ => decoder.skip(wire_type)?,
        }
    }

    if batch.accounts.is_empty() && batch.skipped.is_empty() {
        return Err(Error::MalformedProtobuf);
    }
    Ok(batch)
}

/// Parses one `OtpParameters` sub-message.
///
/// `Ok(Err(..))` is an entry that parsed but cannot be imported; `Err(..)` is a
/// malformed payload.
fn parse_otp_parameters(
    message: &[u8],
) -> Result<core::result::Result<OtpauthUri, SkippedAccount>> {
    let mut secret_bytes: Option<Vec<u8>> = None;
    let mut name = String::new();
    let mut issuer = String::new();
    let mut algorithm = Algorithm::Sha1;
    let mut algorithm_name: Option<String> = None;
    let mut digits = 6_u8;
    let mut is_totp = true;

    let mut decoder = Decoder::new(message);
    while let Some((field, wire_type)) = decoder.next_field()? {
        match (field, wire_type) {
            (1, WireType::LengthDelimited) => secret_bytes = Some(decoder.bytes()?.to_vec()),
            (2, WireType::LengthDelimited) => name = decoder.string()?,
            (3, WireType::LengthDelimited) => issuer = decoder.string()?,
            (4, WireType::Varint) => match decoder.varint()? {
                // ALGO_INVALID is what an older exporter writes for its
                // default, which is SHA1.
                0 | 1 => algorithm = Algorithm::Sha1,
                2 => algorithm = Algorithm::Sha256,
                3 => algorithm = Algorithm::Sha512,
                4 => algorithm_name = Some("MD5".to_owned()),
                other => algorithm_name = Some(other.to_string()),
            },
            (5, WireType::Varint) => {
                digits = match decoder.varint()? {
                    2 => 8,
                    // DIGIT_COUNT_INVALID and SIX both mean six.
                    _ => 6,
                }
            }
            (6, WireType::Varint) => is_totp = decoder.varint()? != 1,
            _ => decoder.skip(wire_type)?,
        }
    }

    // Google Authenticator puts the account in `name`, but exports from other
    // apps reuse the `Issuer:account` label there.
    let (name_issuer, account) = match name.split_once(':') {
        Some((prefix, account)) if !prefix.trim().is_empty() => {
            (Some(prefix.trim().to_owned()), account.trim().to_owned())
        }
        _ => (None, name.trim().to_owned()),
    };
    let issuer = match issuer.trim() {
        "" => name_issuer,
        issuer => Some(issuer.to_owned()),
    };

    let display_name = match (&issuer, account.is_empty()) {
        (Some(issuer), false) => format!("{issuer} ({account})"),
        (Some(issuer), true) => issuer.clone(),
        (None, _) => account.clone(),
    };
    let skip = |reason| {
        Ok(Err(SkippedAccount {
            display_name: display_name.clone(),
            reason,
        }))
    };

    if let Some(name) = algorithm_name {
        return skip(SkipReason::UnsupportedAlgorithm(name));
    }
    if !is_totp {
        return skip(SkipReason::CounterBased);
    }
    let Some(bytes) = secret_bytes else {
        return skip(SkipReason::MalformedSecret);
    };
    let Ok(secret) = Secret::from_bytes(bytes) else {
        return skip(SkipReason::MalformedSecret);
    };

    Ok(Ok(OtpauthUri {
        issuer,
        account,
        secret,
        // The export has no period field: Google Authenticator is always 30s.
        params: TotpParams::new(algorithm, digits, DEFAULT_PERIOD)?,
    }))
}

/// Accumulates the QR codes of one multi-batch export.
#[derive(Debug, Default)]
pub struct MigrationCollector {
    batch_id: Option<i32>,
    expected: usize,
    batches: BTreeMap<i32, MigrationBatch>,
}

impl MigrationCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a scanned URI.
    ///
    /// Re-scanning a code already held replaces it and is not an error, which
    /// is what happens when a user sweeps the camera back over a code.
    pub fn add_uri(&mut self, uri: &str) -> Result<()> {
        self.add(parse_migration_uri(uri)?)
    }

    pub fn add(&mut self, batch: MigrationBatch) -> Result<()> {
        match self.batch_id {
            Some(id) if id != batch.batch_id => return Err(Error::MismatchedBatch),
            Some(_) => {}
            None => {
                self.batch_id = Some(batch.batch_id);
                self.expected = batch.expected_batches();
            }
        }
        // Trust the largest count seen: a truncated field would otherwise let
        // an incomplete import pass as complete.
        self.expected = self.expected.max(batch.expected_batches());
        self.batches.insert(batch.batch_index, batch);
        Ok(())
    }

    /// How many QR codes this export needs in total.
    pub fn expected(&self) -> usize {
        self.expected
    }

    /// How many distinct codes have been scanned.
    pub fn scanned(&self) -> usize {
        self.batches.len()
    }

    /// Batch indexes still missing, for a "scan code 2 of 3" prompt.
    pub fn missing_indexes(&self) -> Vec<i32> {
        (0..self.expected as i32)
            .filter(|index| !self.batches.contains_key(index))
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.expected > 0 && self.batches.len() >= self.expected
    }

    /// Yields the accounts once every code has been scanned.
    pub fn finish(self) -> Result<MigrationImport> {
        if !self.is_complete() {
            return Err(Error::IncompleteBatch {
                got: self.batches.len(),
                expected: self.expected,
            });
        }

        let mut import = MigrationImport::default();
        for (_, batch) in self.batches {
            import.accounts.extend(batch.accounts);
            import.skipped.extend(batch.skipped);
        }
        Ok(import)
    }
}

/// The result of a completed migration import.
#[derive(Debug, Default)]
pub struct MigrationImport {
    pub accounts: Vec<OtpauthUri>,
    pub skipped: Vec<SkippedAccount>,
}
