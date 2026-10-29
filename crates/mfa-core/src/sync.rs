//! Syncing the vault (spec §3).
//!
//! A sync target is any of: a folder the OS already syncs (iCloud Drive,
//! Google Drive, OneDrive), a file in a GitHub or GitLab repository, or a
//! self-hosted sync server. They differ only in how bytes get moved, which is
//! [`crate::platform::SyncProvider`]'s business; to everything here they are
//! the same thing, a file with a revision.
//!
//! # Several targets at once
//!
//! Any number of targets can be enabled together (see
//! [`crate::vault::SyncTarget`]). The local vault is the hub: each target is
//! reconciled against it, and the order does not matter, because
//! [`Vault::merge`] is commutative and idempotent. [`reconcile_all`] does one
//! round over all of them — absorb every copy, dedupe once, then write back to
//! whichever targets are behind.
//!
//! # How the keys work
//!
//! The local vault is encrypted with a data key that never leaves the device's
//! secure store, so it cannot be the key for a file other devices read. A sync
//! set therefore has its own key:
//!
//! - A random 32-byte **sync key** is generated once, on the first device, and
//!   is shared by every target. Copies of the vault are therefore
//!   interchangeable: moving from a cloud folder to a server, or running both,
//!   needs no re-keying.
//! - `mfa-sync.key` holds that key wrapped with the user's password
//!   (Argon2id) — the same password as the encrypted backup, by decision, so
//!   there is only one to remember. Adding a device means entering it once;
//!   the device then keeps the sync key in its own secure store.
//! - `mfa-sync.vault` holds the vault sealed directly with the sync key, so an
//!   ordinary sync costs no key derivation at all.
//!
//! No target ever sees anything but ciphertext, a self-hosted server included.
//! That is what makes running one no more trusted than a cloud drive.
//!
//! # How conflicts work
//!
//! The sync file is opaque ciphertext, so no target — Git and a server
//! included — can merge it. Every sync is therefore read, merge, write, with
//! the write guarded by the revision the read returned. If the revision moved
//! underneath us, we read and merge again rather than overwrite.

use crate::container::{self, Kind};
use crate::crypto::{DataKey, KdfParams};
use crate::error::{Error, Result};
use crate::vault::{MergeReport, Vault};
use crate::Uuid;

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

/// The result of reconciling the local vault against one remote file.
#[derive(Debug)]
pub struct SyncOutcome {
    /// The merged vault, to be stored locally.
    pub merged: Vault,
    /// What the merge changed locally.
    pub report: MergeReport,
    /// Bytes to upload, or `None` when the remote file is already current.
    pub upload: Option<Vec<u8>>,
}

/// One target's remote file as it was fetched.
#[derive(Debug)]
pub struct RemoteState<'a> {
    /// Which target this came from ([`crate::vault::SyncTarget::id`]).
    pub target: Uuid,
    /// The file, or `None` when the target has nothing yet.
    pub bytes: Option<&'a [u8]>,
}

/// A file to write back to one target.
#[derive(Debug)]
pub struct Upload {
    pub target: Uuid,
    pub bytes: Vec<u8>,
}

/// The result of one sync round over every enabled target.
#[derive(Debug)]
pub struct MultiSyncOutcome {
    /// The merged vault, to be stored locally.
    pub merged: Vault,
    /// What the round changed locally, across all targets.
    pub report: MergeReport,
    /// Which targets need writing, and with what.
    pub uploads: Vec<Upload>,
    /// Targets whose file could not be opened, and why.
    ///
    /// Nothing is uploaded to these. A file we cannot read may belong to a
    /// different sync set, and overwriting it would destroy whatever accounts
    /// are in it.
    pub failures: Vec<(Uuid, Error)>,
}

/// Reconciles the local vault against every target in one round.
///
/// Every readable copy is absorbed, duplicates are collapsed once for the
/// whole round, and then each target that is behind — or empty — gets the
/// merged vault. A target already holding it is left alone, so a sync does not
/// churn the user's cloud folder or add an empty commit on a Git target.
pub fn reconcile_all(
    local: &Vault,
    remotes: &[RemoteState<'_>],
    key: &SyncKey,
) -> Result<MultiSyncOutcome> {
    let mut merged = local.clone();
    let mut failures = Vec::new();
    // Keep each target's own copy so we can tell afterwards which ones are
    // already current.
    let mut opened: Vec<(Uuid, Option<Vault>)> = Vec::with_capacity(remotes.len());

    for remote in remotes {
        match remote.bytes {
            None => opened.push((remote.target, None)),
            Some(bytes) => match open(bytes, key) {
                Ok(vault) => {
                    merged.absorb(vault.clone());
                    opened.push((remote.target, Some(vault)));
                }
                Err(error) => failures.push((remote.target, error)),
            },
        }
    }

    let deduped = merged.dedupe();
    let mut report = merged.report_against(local);
    report.deduped = deduped;

    // Seal once and hand the same bytes to every target that needs them: it is
    // the same message, so this is not nonce reuse, and it saves re-encrypting
    // the vault per target.
    let merged_bytes = merged.to_bytes()?;
    let mut sealed: Option<Vec<u8>> = None;
    let mut uploads = Vec::new();
    for (target, remote) in opened {
        let current = match &remote {
            Some(vault) => vault.to_bytes()? == merged_bytes,
            None => false,
        };
        if current {
            continue;
        }
        let bytes = match &sealed {
            Some(bytes) => bytes.clone(),
            None => {
                let bytes = seal(&merged, key)?;
                sealed = Some(bytes.clone());
                bytes
            }
        };
        uploads.push(Upload { target, bytes });
    }

    Ok(MultiSyncOutcome {
        merged,
        report,
        uploads,
        failures,
    })
}

/// Merges one remote file into `local` and decides whether to upload.
///
/// The single-target case of [`reconcile_all`]. `remote` is `None` the first
/// time a device syncs into an empty folder. Unlike `reconcile_all`, a file
/// that cannot be opened is an error rather than a reported failure, because
/// with one target there is nothing else to get on with.
pub fn reconcile(local: &Vault, remote: Option<&[u8]>, key: &SyncKey) -> Result<SyncOutcome> {
    let target = Uuid::nil();
    let mut outcome = reconcile_all(
        local,
        &[RemoteState {
            target,
            bytes: remote,
        }],
        key,
    )?;

    if let Some((_, error)) = outcome.failures.pop() {
        return Err(error);
    }
    Ok(SyncOutcome {
        merged: outcome.merged,
        report: outcome.report,
        upload: outcome.uploads.pop().map(|upload| upload.bytes),
    })
}
