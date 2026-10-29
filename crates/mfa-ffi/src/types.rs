//! The data the bindings exchange.
//!
//! These are plain records rather than the core's types: a UI wants an account
//! it can render in one pass — name, code, seconds left — and it should not be
//! handed a secret it has no use for. Every one also derives serde, because
//! the C ABI in [`crate::capi`] carries the same shapes as JSON.

use serde::{Deserialize, Serialize};

/// One account, ready to render.
///
/// `code` and `remaining_secs` are for the moment the caller asked about, so
/// the list is a pure function of the vault and the clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct AccountView {
    pub id: String,
    pub issuer: Option<String>,
    pub account: String,
    /// `Issuer (account)`, or whichever one exists.
    pub display_name: String,
    pub code: String,
    /// Seconds until `code` changes, in `1..=period`.
    pub remaining_secs: u32,
    pub period: u32,
    pub digits: u8,
    pub algorithm: String,
    pub note: Option<String>,
}

/// What a scanned or pasted URI turns out to hold.
///
/// Deliberately without the secret: a confirmation screen has no use for it,
/// and anything the UI holds can end up in a log or a screenshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct UriPreview {
    pub issuer: Option<String>,
    pub account: String,
    pub display_name: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
}

/// A manually typed account.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct AccountDraft {
    pub issuer: Option<String>,
    pub account: String,
    /// Base32, as printed next to the QR code. Spaces and case do not matter.
    pub secret: String,
    /// `SHA1`, `SHA256` or `SHA512`.
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
}

impl Default for AccountDraft {
    fn default() -> Self {
        Self {
            issuer: None,
            account: String::new(),
            secret: String::new(),
            algorithm: "SHA1".to_owned(),
            digits: 6,
            period: 30,
        }
    }
}

/// What a merge, an import or a sync round changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct MergeSummary {
    pub added: u32,
    pub updated: u32,
    pub deleted: u32,
    /// Collapsed because another entry described exactly the same account.
    pub deduped: u32,
    /// Whether the vault ended up different from how it started. Not implied
    /// by the counters: a duplicate arriving from another device is counted in
    /// `deduped` but leaves the vault as it was.
    pub changed: bool,
}

impl From<mfa_core::MergeReport> for MergeSummary {
    fn from(report: mfa_core::MergeReport) -> Self {
        Self {
            added: report.added as u32,
            updated: report.updated as u32,
            deleted: report.deleted as u32,
            deduped: report.deduped as u32,
            changed: report.changed,
        }
    }
}

/// How far through a multi-QR Google Authenticator export we are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct MigrationProgress {
    pub scanned: u32,
    pub expected: u32,
    pub complete: bool,
    /// Which codes are still missing, for a "scan code 2 of 3" prompt.
    pub missing: Vec<i32>,
}

/// An entry in an export that could not be imported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct SkippedAccountView {
    pub display_name: String,
    pub reason: String,
}

/// The result of a finished import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct ImportResult {
    pub summary: MergeSummary,
    /// Entries the export held that we will not generate codes for. Show
    /// these: a user who is told nothing will assume everything came across.
    pub skipped: Vec<SkippedAccountView>,
}

/// What a backup file says about itself before the password is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct BackupInfo {
    pub format: u8,
    /// Argon2id memory cost in KiB, so a slow unlock can be warned about.
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

/// App-lock settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct LockConfig {
    pub biometric_enabled: bool,
    pub background_timeout_secs: u32,
    /// Whether a PIN fallback is set. The PIN itself never crosses back.
    pub has_pin: bool,
}

/// How the list is ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum SortMode {
    Manual,
    IssuerAsc,
}

/// Everything in settings that is not the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct Preferences {
    pub clipboard_clear_secs: u32,
    pub sort: SortMode,
}

/// What kind of place a sync target is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum)]
pub enum SyncKind {
    /// A folder the OS already syncs: iCloud Drive, Google Drive, OneDrive.
    Folder,
    GitHub,
    GitLab,
    /// A self-hosted sync server.
    Server,
}

/// One configured sync target. Credentials are not here and never travel:
/// they belong in the platform's own secure store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, uniffi::Record)]
pub struct SyncTargetView {
    pub id: String,
    pub kind: SyncKind,
    pub label: String,
    pub location: String,
    pub enabled: bool,
}

/// A target's file as the platform fetched it.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct RemoteFile {
    pub target: String,
    /// `None` when the target has nothing yet.
    #[serde(default, with = "crate::jsonbytes::optional")]
    pub bytes: Option<Vec<u8>>,
}

/// A file to write back to one target.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct UploadRequest {
    pub target: String,
    #[serde(with = "crate::jsonbytes::required")]
    pub bytes: Vec<u8>,
}

/// A target whose file could not be opened.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct SyncFailure {
    pub target: String,
    pub message: String,
}

/// The result of one sync round.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct SyncRound {
    pub summary: MergeSummary,
    /// Write these back, each guarded by the revision it was read at.
    pub uploads: Vec<UploadRequest>,
    /// Nothing is uploaded to these: a file we cannot read may belong to
    /// someone else's sync set.
    pub failures: Vec<SyncFailure>,
}
