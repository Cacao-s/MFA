//! Foreign-function bindings for `mfa-core`.
//!
//! The core is plain Rust with no I/O; this crate makes it callable from the
//! platform shells. Two surfaces over one implementation:
//!
//! - **UniFFI**, for Swift (macOS and iOS) and Kotlin (Android). Generated
//!   typed bindings — see `README.md` for the two commands.
//! - **A JSON command bus over the C ABI** ([`capi`]), for Windows and
//!   anything else without a first-party generator. Two exported functions
//!   total, so a C# `DllImport` is a few lines.
//!
//! Both go through [`VaultHandle`], so there is one set of rules and one place
//! a bug can live.
//!
//! # What the platform is responsible for
//!
//! Everything the core deliberately does not do:
//!
//! | Thing | Why it is yours |
//! |---|---|
//! | The data key, in the OS secure store | The whole security model rests on the OS holding it, not us |
//! | Reading and writing the vault file | Write atomically: temporary file, then rename |
//! | The clock | Every call takes `now_ms` or `now_secs`, so behaviour is reproducible |
//! | Network calls for sync | You fetch bytes, call [`VaultHandle::sync`], write back what it returns |
//! | Biometrics, camera, clipboard | Platform APIs; `mfa_core::platform` says what each has to guarantee |

uniffi::setup_scaffolding!();

pub mod capi;
pub mod error;
pub mod handle;
pub mod jsonbytes;
pub mod types;

pub use error::{ErrorKind, MfaError};
pub use handle::VaultHandle;
pub use types::*;

use mfa_core::crypto::{DataKey, KdfParams};
use mfa_core::migration::MigrationCollector;
use mfa_core::{backup, sync, OtpauthUri};

use crate::error::Result;

/// A fresh 32-byte vault data key, from the OS CSPRNG.
///
/// Put it in the platform's secure store **before** sealing a vault with it:
/// if it is lost, the vault file cannot be read again.
#[uniffi::export]
pub fn generate_data_key() -> Vec<u8> {
    DataKey::generate().expose().to_vec()
}

/// A fresh sync key, for the first device in a new sync set.
///
/// Every target in the set shares it, so their files are interchangeable.
#[uniffi::export]
pub fn new_sync_key() -> Vec<u8> {
    sync::new_sync_key().expose().to_vec()
}

/// Wraps the sync key with the user's password, for the `mfa-sync.key` file
/// that other devices read to join.
///
/// This is the same password as the backup password: there is only one.
#[uniffi::export]
pub fn wrap_sync_key(sync_key: Vec<u8>, password: String) -> Result<Vec<u8>> {
    let key = DataKey::from_slice(&sync_key)?;
    Ok(sync::wrap_key(&key, &password, &KdfParams::default())?)
}

/// Unwraps `mfa-sync.key` when a device joins a sync set.
///
/// Store the result in the platform's secure store; after that, syncing needs
/// no password and no key derivation.
#[uniffi::export]
pub fn unwrap_sync_key(key_file: Vec<u8>, password: String) -> Result<Vec<u8>> {
    Ok(sync::unwrap_key(&key_file, &password)?.expose().to_vec())
}

/// What a scanned or pasted `otpauth://` URI holds, for a confirmation screen.
///
/// Without the secret: a confirmation screen has no use for it.
#[uniffi::export]
pub fn preview_uri(uri: String) -> Result<UriPreview> {
    let parsed = OtpauthUri::parse(&uri)?;
    Ok(UriPreview {
        issuer: parsed.issuer.clone(),
        account: parsed.account.clone(),
        display_name: parsed.display_name(),
        algorithm: parsed.params.algorithm.as_str().to_owned(),
        digits: parsed.params.digits,
        period: parsed.params.period,
    })
}

/// How far through a multi-QR Google Authenticator export the scanned URIs
/// get, so the UI can say "scan code 2 of 3".
///
/// Keep the scanned strings on the platform side and pass them all each time;
/// nothing is remembered here.
#[uniffi::export]
pub fn migration_progress(uris: Vec<String>) -> Result<MigrationProgress> {
    let mut collector = MigrationCollector::new();
    for uri in &uris {
        collector.add_uri(uri)?;
    }
    Ok(MigrationProgress {
        scanned: collector.scanned() as u32,
        expected: collector.expected() as u32,
        complete: collector.is_complete(),
        missing: collector.missing_indexes(),
    })
}

/// What a backup file says about itself before the password is asked for.
///
/// Use it to warn before a slow derivation, and to tell a backup apart from
/// some other file the user picked.
#[uniffi::export]
pub fn inspect_backup(file: Vec<u8>) -> Result<BackupInfo> {
    let info = backup::inspect(&file)?;
    let kdf = info.kdf.unwrap_or_default();
    Ok(BackupInfo {
        format: info.format,
        memory_kib: kdf.m_cost,
        iterations: kdf.t_cost,
        lanes: kdf.p_cost,
    })
}

/// Reads every QR code in an image or screen grab, returning their payloads.
///
/// The desktop way to add an account. Mobile cameras stay on the platform
/// side: pass whatever the scanner decoded to [`VaultHandle::add_uri`].
#[cfg(feature = "qr-image")]
#[uniffi::export]
pub fn decode_qr_image(image: Vec<u8>) -> Result<Vec<String>> {
    Ok(mfa_core::qr::decode_otp_uris(&image)?)
}

/// This library's version, for an about screen and for bug reports.
#[uniffi::export]
pub fn library_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
