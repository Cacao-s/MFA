//! The error type the bindings see.
//!
//! Every platform needs two things from a failure: something to show the user,
//! and enough structure to decide what to do next — a wrong backup password
//! means ask again, a corrupt file means do not. So the error carries a
//! message and a kind, and nothing else; the core's variants are a detail the
//! UI should not have to match on exhaustively.

use mfa_core::Error as CoreError;

/// What kind of failure it was, for the UI to branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, uniffi::Enum)]
pub enum ErrorKind {
    /// The QR code or pasted text was not something we can add.
    BadUri,
    /// The secret or the TOTP parameters are unusable.
    BadAccount,
    /// The backup password was wrong. Ask again.
    WrongPassword,
    /// The file is for us but will not decrypt with the key we have.
    CannotDecrypt,
    /// The file is truncated, altered, or not one of ours.
    BadFile,
    /// Written by a newer version of the app.
    TooNew,
    /// A Google Authenticator export that is not fully scanned yet.
    IncompleteImport,
    /// No account with that id.
    NotFound,
    /// Something we deliberately do not support, such as HOTP.
    Unsupported,
    /// The image held no QR code.
    NoQrCode,
    /// Anything else.
    Other,
}

/// A failure, as the bindings see it.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MfaError {
    #[error("{message}")]
    Failed { kind: ErrorKind, message: String },
}

impl MfaError {
    pub fn kind(&self) -> ErrorKind {
        match self {
            MfaError::Failed { kind, .. } => *kind,
        }
    }

    pub(crate) fn of(kind: ErrorKind, message: impl Into<String>) -> Self {
        MfaError::Failed {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn not_found(id: &str) -> Self {
        Self::of(ErrorKind::NotFound, format!("no account with id {id}"))
    }
}

impl From<CoreError> for MfaError {
    fn from(error: CoreError) -> Self {
        // The message is always the core's own: it is written to be shown.
        let kind = match &error {
            CoreError::NotOtpauthUri
            | CoreError::NotMigrationUri
            | CoreError::MissingSecret
            | CoreError::MissingLabel
            | CoreError::InvalidParameter(..)
            | CoreError::InvalidPercentEncoding
            | CoreError::MalformedMigrationData
            | CoreError::MalformedProtobuf
            | CoreError::MismatchedBatch => ErrorKind::BadUri,

            CoreError::InvalidSecret
            | CoreError::EmptySecret
            | CoreError::UnsupportedAlgorithm(_)
            | CoreError::UnsupportedDigits(_)
            | CoreError::UnsupportedPeriod(_) => ErrorKind::BadAccount,

            CoreError::WrongPassword => ErrorKind::WrongPassword,
            CoreError::DecryptionFailed => ErrorKind::CannotDecrypt,

            CoreError::WrongFileKind { .. }
            | CoreError::CorruptFile
            | CoreError::MalformedVault
            | CoreError::UnsupportedCipher(_)
            | CoreError::UnsupportedKdf(_)
            | CoreError::KeyDerivationFailed => ErrorKind::BadFile,

            CoreError::NoSuchAccount => ErrorKind::NotFound,
            CoreError::UnsupportedFormat { .. } => ErrorKind::TooNew,
            CoreError::IncompleteBatch { .. } => ErrorKind::IncompleteImport,
            CoreError::UnsupportedOtpType(_) => ErrorKind::Unsupported,

            CoreError::UnreadableImage | CoreError::NoQrCodeFound => ErrorKind::NoQrCode,

            _ => ErrorKind::Other,
        };
        MfaError::of(kind, error.to_string())
    }
}

pub type Result<T> = core::result::Result<T, MfaError>;
