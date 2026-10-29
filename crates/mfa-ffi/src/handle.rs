//! The handle a platform holds on to.
//!
//! The core is free of I/O on purpose, and that stays true here: this object
//! holds the decrypted vault and its data key in memory, and the platform does
//! every bit of reading, writing and networking. So the shape of a session is
//! always the same on all four platforms:
//!
//! 1. Get the data key from the platform's secure store, or
//!    [`crate::generate_data_key`] on first run.
//! 2. [`VaultHandle::open`] the vault file the platform read, or
//!    [`VaultHandle::create`] if there is none.
//! 3. Call methods. After anything that changes the vault, call
//!    [`VaultHandle::seal`] and write the bytes back.
//!
//! Time is always passed in — `now_ms` for edits, `now_secs` for codes — so
//! the vault never reads a clock and the same call is reproducible in a test.

use std::sync::Mutex;

use mfa_core::backup;
use mfa_core::crypto::{DataKey, KdfParams};
use mfa_core::migration::MigrationCollector;
use mfa_core::pin::PinVerifier;
use mfa_core::sync::{self, RemoteState};
use mfa_core::vault::{self, Account, Entry};
use mfa_core::{OtpauthUri, Uuid, Vault};

use crate::error::{ErrorKind, MfaError, Result};
use crate::types::*;

/// An open vault.
#[derive(Debug, uniffi::Object)]
pub struct VaultHandle {
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    vault: Vault,
    key: DataKey,
}

#[uniffi::export]
impl VaultHandle {
    /// An empty vault, for a first run.
    ///
    /// `data_key` comes from [`crate::generate_data_key`] and must be put in
    /// the platform's secure store before the vault is sealed, or the file
    /// will not be readable again.
    #[uniffi::constructor]
    pub fn create(data_key: Vec<u8>) -> Result<Self> {
        Self::with(Vault::new(), data_key)
    }

    /// Opens a vault file read by the platform.
    #[uniffi::constructor]
    pub fn open(data_key: Vec<u8>, file: Vec<u8>) -> Result<Self> {
        let key = data_key_from(&data_key)?;
        let vault = Vault::open(&key, &file)?;
        Ok(Self {
            state: Mutex::new(State { vault, key }),
        })
    }

    /// The encrypted vault, to be written back by the platform.
    ///
    /// Write it atomically — temporary file, then rename — or a crash during
    /// the write can leave a vault that no longer decrypts.
    pub fn seal(&self) -> Result<Vec<u8>> {
        let state = self.lock();
        Ok(state.vault.seal(&state.key)?)
    }

    /// How many accounts there are.
    pub fn count(&self) -> u32 {
        self.lock().vault.len() as u32
    }

    /// Every account, in display order, with its code at `now_secs`.
    pub fn accounts(&self, now_secs: u64) -> Result<Vec<AccountView>> {
        let state = self.lock();
        state
            .vault
            .visible()
            .into_iter()
            .map(|entry| view(entry, now_secs))
            .collect()
    }

    /// The accounts matching `query`, in display order. An empty query
    /// matches everything, so a cleared search box shows the full list.
    pub fn search(&self, query: String, now_secs: u64) -> Result<Vec<AccountView>> {
        let state = self.lock();
        state
            .vault
            .search(&query)
            .into_iter()
            .map(|entry| view(entry, now_secs))
            .collect()
    }

    /// One account's code at `now_secs`.
    pub fn code(&self, id: String, now_secs: u64) -> Result<String> {
        let state = self.lock();
        Ok(state.vault.code_at(parse_id(&id)?, now_secs)?)
    }

    /// The account as an `otpauth://` URI.
    ///
    /// **This contains the secret.** It is what a "show QR code to move this
    /// to another app" screen needs, and it should not be used for anything
    /// else — not logged, not put on the clipboard without asking.
    pub fn account_uri(&self, id: String) -> Result<String> {
        let state = self.lock();
        let entry = state
            .vault
            .get(parse_id(&id)?)
            .ok_or_else(|| MfaError::not_found(&id))?;
        let account = entry
            .account
            .as_ref()
            .ok_or_else(|| MfaError::not_found(&id))?;
        Ok(account.to_uri().to_uri_string())
    }

    /// Adds an account from a scanned or pasted `otpauth://` URI.
    ///
    /// If the same account is already there, nothing is added and its id comes
    /// back. Check with [`VaultHandle::duplicate_of_uri`] first if the UI
    /// wants to say so.
    pub fn add_uri(&self, uri: String, now_ms: i64) -> Result<String> {
        let parsed = OtpauthUri::parse(&uri)?;
        let mut state = self.lock();
        Ok(state.vault.add(parsed, now_ms).to_string())
    }

    /// The id of an account identical to what this URI describes, if any.
    pub fn duplicate_of_uri(&self, uri: String) -> Result<Option<String>> {
        let parsed = OtpauthUri::parse(&uri)?;
        let state = self.lock();
        Ok(state
            .vault
            .find_duplicate(&Account::from(parsed))
            .map(|id| id.to_string()))
    }

    /// Adds a manually typed account.
    pub fn add_manual(&self, draft: AccountDraft, now_ms: i64) -> Result<String> {
        let account = account_from(draft)?;
        let mut state = self.lock();
        Ok(state.vault.add(account, now_ms).to_string())
    }

    /// Changes an account's note, or clears it with `None`.
    pub fn set_note(&self, id: String, note: Option<String>, now_ms: i64) -> Result<()> {
        let id = parse_id(&id)?;
        let mut state = self.lock();
        Ok(state.vault.update(id, now_ms, |account| {
            account.note = note.filter(|note| !note.trim().is_empty());
        })?)
    }

    /// Renames an account.
    pub fn rename(
        &self,
        id: String,
        issuer: Option<String>,
        account_name: String,
        now_ms: i64,
    ) -> Result<()> {
        let id = parse_id(&id)?;
        let mut state = self.lock();
        Ok(state.vault.update(id, now_ms, |account| {
            account.issuer = issuer.filter(|issuer| !issuer.trim().is_empty());
            account.account = account_name;
        })?)
    }

    /// Deletes an account.
    ///
    /// A tombstone stays behind so that the next sync does not bring it back
    /// from a device that has not caught up yet.
    pub fn delete(&self, id: String, now_ms: i64) -> Result<()> {
        let id = parse_id(&id)?;
        let mut state = self.lock();
        Ok(state.vault.delete(id, now_ms)?)
    }

    /// Applies a drag-and-drop order. Ids left out keep their position after
    /// the ones listed.
    pub fn reorder(&self, ids: Vec<String>, now_ms: i64) -> Result<()> {
        let ids: Result<Vec<Uuid>> = ids.iter().map(|id| parse_id(id)).collect();
        let mut state = self.lock();
        state.vault.reorder(&ids?, now_ms);
        Ok(())
    }

    /// Drops tombstones old enough that no device could still need them.
    pub fn prune_tombstones(&self, now_ms: i64) -> u32 {
        let mut state = self.lock();
        state
            .vault
            .prune_tombstones(now_ms, vault::TOMBSTONE_RETENTION_MS) as u32
    }

    // --- Google Authenticator import ------------------------------------

    /// Imports every account from a set of scanned `otpauth-migration://`
    /// URIs.
    ///
    /// A large export is split over several QR codes; pass all of them. Use
    /// [`crate::migration_progress`] while scanning to know whether any are
    /// still missing — an incomplete set is an error here rather than a
    /// partial import that looks finished.
    pub fn import_migration(&self, uris: Vec<String>, now_ms: i64) -> Result<ImportResult> {
        let mut collector = MigrationCollector::new();
        for uri in &uris {
            collector.add_uri(uri)?;
        }
        let imported = collector.finish()?;

        let mut state = self.lock();
        let before = state.vault.clone();
        for account in imported.accounts {
            state.vault.add(account, now_ms);
        }
        let summary = state.vault.report_against(&before);

        Ok(ImportResult {
            summary: summary.into(),
            skipped: imported
                .skipped
                .into_iter()
                .map(|skipped| SkippedAccountView {
                    display_name: skipped.display_name,
                    reason: skipped.reason.to_string(),
                })
                .collect(),
        })
    }

    // --- backup ----------------------------------------------------------

    /// Encrypts the vault for export, with the user's password.
    ///
    /// This is the same password as the sync password: there is only one.
    pub fn export_backup(&self, password: String) -> Result<Vec<u8>> {
        let state = self.lock();
        Ok(backup::export(
            &state.vault,
            &password,
            &KdfParams::default(),
        )?)
    }

    /// Imports a backup, merging rather than replacing.
    ///
    /// The vault is untouched unless the whole file decrypted and parsed, so a
    /// wrong password cannot leave a half-restored vault.
    pub fn import_backup(&self, file: Vec<u8>, password: String) -> Result<MergeSummary> {
        let mut state = self.lock();
        Ok(backup::import_into(&mut state.vault, &file, &password)?.into())
    }

    // --- settings --------------------------------------------------------

    pub fn lock_config(&self) -> LockConfig {
        let lock = &self.lock().vault.settings.lock;
        LockConfig {
            biometric_enabled: lock.biometric_enabled,
            background_timeout_secs: lock.background_timeout_secs,
            has_pin: lock.pin.is_some(),
        }
    }

    /// Changes the lock settings. The PIN is set separately, by
    /// [`VaultHandle::set_pin`].
    pub fn set_lock_config(&self, config: LockConfig, now_ms: i64) {
        let mut state = self.lock();
        let mut settings = state.vault.settings.clone();
        settings.lock.biometric_enabled = config.biometric_enabled;
        settings.lock.background_timeout_secs = config.background_timeout_secs;
        state.vault.set_settings(settings, now_ms);
    }

    /// Sets the PIN fallback. Only a verifier is stored, never the PIN.
    pub fn set_pin(&self, pin: String, now_ms: i64) -> Result<()> {
        let verifier = PinVerifier::new(&pin, &KdfParams::default())?;
        let mut state = self.lock();
        let mut settings = state.vault.settings.clone();
        settings.lock.pin = Some(verifier);
        state.vault.set_settings(settings, now_ms);
        Ok(())
    }

    pub fn clear_pin(&self, now_ms: i64) {
        let mut state = self.lock();
        let mut settings = state.vault.settings.clone();
        settings.lock.pin = None;
        state.vault.set_settings(settings, now_ms);
    }

    /// Checks a PIN. `false` when none is set, so a missing PIN never unlocks.
    pub fn verify_pin(&self, pin: String) -> bool {
        self.lock()
            .vault
            .settings
            .lock
            .pin
            .as_ref()
            .is_some_and(|verifier| verifier.verify(&pin))
    }

    pub fn preferences(&self) -> Preferences {
        let settings = &self.lock().vault.settings;
        Preferences {
            clipboard_clear_secs: settings.clipboard_clear_secs,
            sort: match settings.sort {
                vault::SortMode::Manual => SortMode::Manual,
                vault::SortMode::IssuerAsc => SortMode::IssuerAsc,
            },
        }
    }

    pub fn set_preferences(&self, preferences: Preferences, now_ms: i64) {
        let mut state = self.lock();
        let mut settings = state.vault.settings.clone();
        settings.clipboard_clear_secs = preferences.clipboard_clear_secs;
        settings.sort = match preferences.sort {
            SortMode::Manual => vault::SortMode::Manual,
            SortMode::IssuerAsc => vault::SortMode::IssuerAsc,
        };
        state.vault.set_settings(settings, now_ms);
    }

    // --- sync ------------------------------------------------------------

    /// The configured sync targets. Any number can be enabled at once.
    pub fn sync_targets(&self) -> Vec<SyncTargetView> {
        self.lock()
            .vault
            .settings
            .sync
            .iter()
            .map(target_view)
            .collect()
    }

    /// Adds a target, or updates it if `target.id` names one. Returns its id.
    ///
    /// Leave `id` empty to add. Credentials are not part of this: keep the
    /// token or password in the platform's secure store, because settings
    /// travel to the other devices and credentials must not.
    pub fn upsert_sync_target(&self, target: SyncTargetView, now_ms: i64) -> Result<String> {
        let id = if target.id.trim().is_empty() {
            Uuid::new_v4()
        } else {
            parse_id(&target.id)?
        };

        let updated = vault::SyncTarget {
            id,
            kind: match target.kind {
                SyncKind::Folder => vault::SyncTargetKind::Folder,
                SyncKind::GitHub => vault::SyncTargetKind::GitHub,
                SyncKind::GitLab => vault::SyncTargetKind::GitLab,
                SyncKind::Server => vault::SyncTargetKind::Server,
            },
            label: target.label,
            location: target.location,
            enabled: target.enabled,
        };

        let mut state = self.lock();
        let mut settings = state.vault.settings.clone();
        match settings.sync.iter_mut().find(|existing| existing.id == id) {
            Some(existing) => *existing = updated,
            None => settings.sync.push(updated),
        }
        state.vault.set_settings(settings, now_ms);
        Ok(id.to_string())
    }

    pub fn remove_sync_target(&self, id: String, now_ms: i64) -> Result<()> {
        let id = parse_id(&id)?;
        let mut state = self.lock();
        let mut settings = state.vault.settings.clone();
        settings.sync.retain(|target| target.id != id);
        state.vault.set_settings(settings, now_ms);
        Ok(())
    }

    /// One sync round against every target the platform fetched.
    ///
    /// The platform does the network calls and passes the bytes in. Write each
    /// returned upload back **guarded by the revision it was read at**; if a
    /// write is refused because the revision moved, fetch again and call this
    /// again. Nothing is returned for a target whose file could not be opened:
    /// it may belong to another sync set.
    ///
    /// Call [`VaultHandle::seal`] afterwards and store the result locally.
    pub fn sync(&self, remotes: Vec<RemoteFile>, sync_key: Vec<u8>) -> Result<SyncRound> {
        let key = data_key_from(&sync_key)?;
        let targets: Result<Vec<(Uuid, Option<Vec<u8>>)>> = remotes
            .into_iter()
            .map(|remote| Ok((parse_id(&remote.target)?, remote.bytes)))
            .collect();
        let targets = targets?;

        let states: Vec<RemoteState<'_>> = targets
            .iter()
            .map(|(target, bytes)| RemoteState {
                target: *target,
                bytes: bytes.as_deref(),
            })
            .collect();

        let mut state = self.lock();
        let outcome = sync::reconcile_all(&state.vault, &states, &key)?;
        state.vault = outcome.merged;

        Ok(SyncRound {
            summary: outcome.report.into(),
            uploads: outcome
                .uploads
                .into_iter()
                .map(|upload| UploadRequest {
                    target: upload.target.to_string(),
                    bytes: upload.bytes,
                })
                .collect(),
            failures: outcome
                .failures
                .into_iter()
                .map(|(target, error)| SyncFailure {
                    target: target.to_string(),
                    message: error.to_string(),
                })
                .collect(),
        })
    }
}

impl VaultHandle {
    fn with(vault: Vault, data_key: Vec<u8>) -> Result<Self> {
        Ok(Self {
            state: Mutex::new(State {
                vault,
                key: data_key_from(&data_key)?,
            }),
        })
    }

    /// The lock is only ever held inside one method, so it cannot deadlock;
    /// a poisoned lock means a method panicked, which is a bug either way.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn data_key_from(bytes: &[u8]) -> Result<DataKey> {
    DataKey::from_slice(bytes).map_err(|_| {
        MfaError::of(
            ErrorKind::BadAccount,
            format!("a key must be 32 bytes, got {}", bytes.len()),
        )
    })
}

fn parse_id(id: &str) -> Result<Uuid> {
    Uuid::parse_str(id).map_err(|_| MfaError::not_found(id))
}

fn account_from(draft: AccountDraft) -> Result<Account> {
    use core::str::FromStr as _;
    use mfa_core::totp::{Algorithm, TotpParams};
    use mfa_core::Secret;

    Ok(Account {
        issuer: draft.issuer.filter(|issuer| !issuer.trim().is_empty()),
        account: draft.account,
        secret: Secret::from_base32(&draft.secret)?,
        totp: TotpParams::new(
            Algorithm::from_str(&draft.algorithm)?,
            draft.digits,
            draft.period,
        )?,
        note: None,
    })
}

fn view(entry: &Entry, now_secs: u64) -> Result<AccountView> {
    let account = entry
        .account
        .as_ref()
        .ok_or_else(|| MfaError::of(ErrorKind::NotFound, "a deleted account has no code"))?;

    Ok(AccountView {
        id: entry.id.to_string(),
        issuer: account.issuer.clone(),
        account: account.account.clone(),
        display_name: account.display_name(),
        code: account.code_at(now_secs)?,
        remaining_secs: account.totp.remaining_secs_at(now_secs),
        period: account.totp.period,
        digits: account.totp.digits,
        algorithm: account.totp.algorithm.as_str().to_owned(),
        note: account.note.clone(),
    })
}

fn target_view(target: &vault::SyncTarget) -> SyncTargetView {
    SyncTargetView {
        id: target.id.to_string(),
        kind: match target.kind {
            vault::SyncTargetKind::Folder => SyncKind::Folder,
            vault::SyncTargetKind::GitHub => SyncKind::GitHub,
            vault::SyncTargetKind::GitLab => SyncKind::GitLab,
            vault::SyncTargetKind::Server => SyncKind::Server,
        },
        label: target.label.clone(),
        location: target.location.clone(),
        enabled: target.enabled,
    }
}
