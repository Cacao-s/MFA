//! Platform-independent core of the MFA authenticator.
//!
//! Everything here is pure: no filesystem, no clock, no network. Time arrives
//! as a `u64` of seconds since the Unix epoch and files arrive as byte slices,
//! so the same code runs and is tested identically on all four platforms.
//!
//! The pieces:
//!
//! - [`totp`] — RFC 4226 / RFC 6238 code generation.
//! - [`uri`] — `otpauth://` parsing and generation.
//! - [`migration`] — Google Authenticator `otpauth-migration://` imports.
//! - [`vault`] — the account document, its tombstones and its merge rule.
//! - [`crypto`] — XChaCha20-Poly1305 and Argon2id primitives.
//! - [`container`] — the on-disk envelope shared by vault and backup files.
//! - [`backup`] — password-protected export and import.
//! - [`sync`] — merging a vault against a copy from a file-sync provider.
//! - [`platform`] — the traits each platform shell has to implement.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod backup;
pub mod container;
pub mod crypto;
pub mod error;
pub mod migration;
pub mod pin;
pub mod platform;
mod protobuf;
#[cfg(feature = "qr-image")]
pub mod qr;
pub mod secret;
pub mod sync;
pub mod totp;
pub mod uri;
pub mod vault;

pub use error::{Error, Result};
// Re-exported so a platform shell does not need to depend on `uuid` itself.
pub use migration::{MigrationBatch, MigrationCollector, MigrationImport};
pub use secret::Secret;
pub use totp::{Algorithm, TotpParams};
pub use uri::OtpauthUri;
pub use uuid::Uuid;
pub use vault::{Account, Entry, MergeReport, Settings, SyncTarget, SyncTargetKind, Vault};
