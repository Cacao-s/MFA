//! Syncing the vault through a file the user already has in the cloud
//! (spec §3: iCloud Drive, Google Drive, OneDrive, or a Git repository).
//!
//! # How the keys work
//!
//! The local vault is encrypted with a data key that never leaves the device's
//! secure store, so it cannot be the key for a file other devices read. A sync
//! set therefore has its own key:
//!
//! - A random 32-byte **sync key** is generated once, on the first device.
//! - `mfa-sync.key` holds that key wrapped with the user's sync password
//!   (Argon2id). Adding a device means entering the password once; the device
//!   then keeps the sync key in its own secure store.
//! - `mfa-sync.vault` holds the vault sealed directly with the sync key, so an
//!   ordinary sync costs no key derivation at all.
//!
//! The provider only ever sees ciphertext.
//!
//! # How conflicts work
//!
//! The sync file is opaque ciphertext, so no provider — Git included — can
//! merge it. Every sync is therefore read, merge, write, with the merge done
//! by [`Vault::merge`], and the write guarded by the revision the read
//! returned (see [`crate::platform::SyncProvider`]). If the revision moved
//! underneath us, we read and merge again rather than overwrite.

use crate::container::{self, Kind};
use crate::crypto::{DataKey, KdfParams};
use crate::error::Result;
use crate::vault::{MergeReport, Vault};

/// Conventional file names inside the user's sync folder.
pub const VAULT_FILE_NAME: &str = "mfa-sync.vault";
pub const KEY_FILE_NAME: &str = "mfa-sync.key";

/// The key shared by every device in one sync set.
pub type SyncKey = DataKey;

/// Generates the key for a new sync set.
pub fn new_sync_key() -> SyncKey {
    DataKey::generate()
}

/// Wraps the sync key with the user's sync password, for `mfa-sync.key`.
pub fn wrap_key(key: &SyncKey, password: &str, kdf: &KdfParams) -> Result<Vec<u8>> {
    container::seal_with_password(Kind::Backup, password, kdf, key.expose())
}

/// Unwraps `mfa-sync.key` when enrolling a new device.
pub fn unwrap_key(bytes: &[u8], password: &str) -> Result<SyncKey> {
    let raw = container::open_with_password(Kind::Backup, password, bytes)?;
    DataKey::from_slice(&raw)
}

/// Seals the vault for upload.
pub fn seal(vault: &Vault, key: &SyncKey) -> Result<Vec<u8>> {
    container::seal_with_key(Kind::Sync, key, &vault.to_bytes()?)
}

/// Opens a downloaded sync file.
pub fn open(bytes: &[u8], key: &SyncKey) -> Result<Vault> {
    Vault::from_bytes(&container::open_with_key(Kind::Sync, key, bytes)?)
}

/// The result of reconciling the local vault against the remote file.
#[derive(Debug)]
pub struct SyncOutcome {
    /// The merged vault, to be stored locally.
    pub merged: Vault,
    /// What the merge changed locally.
    pub report: MergeReport,
    /// Bytes to upload, or `None` when the remote file is already current.
    pub upload: Option<Vec<u8>>,
}

/// Merges the remote file into `local` and decides whether to upload.
///
/// `remote` is `None` the first time a device syncs into an empty folder.
pub fn reconcile(local: &Vault, remote: Option<&[u8]>, key: &SyncKey) -> Result<SyncOutcome> {
    let Some(remote_bytes) = remote else {
        // Nothing there yet: publish what we have.
        return Ok(SyncOutcome {
            merged: local.clone(),
            report: MergeReport::default(),
            upload: Some(seal(local, key)?),
        });
    };

    let remote_vault = open(remote_bytes, key)?;
    let mut merged = local.clone();
    let report = merged.merge(remote_vault.clone());

    // Compare documents, not ciphertext: every seal uses a fresh nonce, so
    // identical vaults never produce identical bytes.
    let upload = if merged.to_bytes()? == remote_vault.to_bytes()? {
        None
    } else {
        Some(seal(&merged, key)?)
    };

    Ok(SyncOutcome {
        merged,
        report,
        upload,
    })
}
