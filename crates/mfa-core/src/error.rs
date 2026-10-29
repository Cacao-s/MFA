//! Error type for the whole core.
//!
//! No variant ever carries secret material: messages are safe to log and to
//! show to a user verbatim.

/// Everything that can go wrong inside `mfa-core`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // --- otpauth:// URIs -------------------------------------------------
    #[error("not an otpauth:// URI")]
    NotOtpauthUri,

    #[error("not an otpauth-migration:// URI")]
    NotMigrationUri,

    #[error("unsupported OTP type `{0}`: this version only supports TOTP")]
    UnsupportedOtpType(String),

    #[error("the URI has no `secret` parameter")]
    MissingSecret,

    #[error("the URI has no account label")]
    MissingLabel,

    #[error("`{0}` is not a valid value for `{1}`")]
    InvalidParameter(String, &'static str),

    #[error("percent-encoding in the URI is not valid UTF-8")]
    InvalidPercentEncoding,

    // --- secrets and TOTP parameters ------------------------------------
    #[error("the secret is not valid Base32")]
    InvalidSecret,

    #[error("the secret is empty")]
    EmptySecret,

    #[error("unsupported algorithm `{0}`: use SHA1, SHA256 or SHA512")]
    UnsupportedAlgorithm(String),

    #[error("unsupported digit count {0}: use 6, 7 or 8")]
    UnsupportedDigits(u8),

    #[error("the period must be between 1 and 3600 seconds, got {0}")]
    UnsupportedPeriod(u32),

    // --- Google Authenticator migration payloads -------------------------
    #[error("the migration payload is not valid protobuf")]
    MalformedProtobuf,

    #[error("the migration payload is not valid Base64")]
    MalformedMigrationData,

    #[error("these migration QR codes belong to different exports; re-export and scan one set")]
    MismatchedBatch,

    #[error("the migration export is incomplete: {got} of {expected} QR codes scanned")]
    IncompleteBatch { got: usize, expected: usize },

    // --- container / vault files ----------------------------------------
    #[error("this is not an MFA {expected} file")]
    WrongFileKind { expected: &'static str },

    #[error("this file was written by a newer version of MFA (format {found}, this build reads up to {supported})")]
    UnsupportedFormat { found: u8, supported: u8 },

    #[error("the file is truncated or corrupt")]
    CorruptFile,

    #[error("unsupported cipher `{0}` in the file header")]
    UnsupportedCipher(String),

    #[error("unsupported key-derivation function `{0}` in the file header")]
    UnsupportedKdf(String),

    #[error("wrong password, or the file has been altered")]
    WrongPassword,

    #[error("the vault could not be decrypted with the stored key; it may have been altered")]
    DecryptionFailed,

    #[error("the file contents are not valid MFA vault data")]
    MalformedVault,

    #[error("key derivation failed")]
    KeyDerivationFailed,

    // --- QR decoding (feature `qr-image`) --------------------------------
    #[error("that image could not be read")]
    UnreadableImage,

    #[error("no QR code was found in the image")]
    NoQrCodeFound,
}

/// `Result` with [`Error`] as the error type.
pub type Result<T> = core::result::Result<T, Error>;
