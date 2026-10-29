//! The account document: what is stored, and how two copies of it merge.
//!
//! Every entry carries a UUID, a modification time and a tombstone flag from
//! v1, so adding file-based sync later (spec §3) needs no format change. The
//! merge rule is deterministic and commutative — `merge(a, b)` and
//! `merge(b, a)` produce the same document — which is what makes two devices
//! writing the same file converge instead of ping-ponging.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::container::{self, Kind};
use crate::crypto::DataKey;
use crate::error::{Error, Result};
use crate::pin::PinVerifier;
use crate::secret::Secret;
use crate::totp::TotpParams;
use crate::uri::OtpauthUri;

/// Milliseconds since the Unix epoch. Time is always passed in, never read.
pub type Millis = i64;

/// The document format version this build writes.
pub const VAULT_FORMAT: u32 = 1;

/// How long a tombstone is kept. It has to outlive the longest plausible gap
/// between a device's syncs, or deleting on one device and syncing months
/// later on another would resurrect the account.
pub const TOMBSTONE_RETENTION_MS: Millis = 180 * 24 * 60 * 60 * 1000;

/// Default seconds in the background before the app locks again (spec §4).
pub const DEFAULT_BACKGROUND_TIMEOUT_SECS: u32 = 30;
/// Default seconds before a copied code is cleared from the clipboard.
pub const DEFAULT_CLIPBOARD_CLEAR_SECS: u32 = 30;

/// One account's data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    pub account: String,
    pub secret: Secret,
    pub totp: TotpParams,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Account {
    /// What the list shows: `Issuer (account)`, or whichever one exists.
    pub fn display_name(&self) -> String {
        match (&self.issuer, self.account.is_empty()) {
            (Some(issuer), false) => format!("{issuer} ({})", self.account),
            (Some(issuer), true) => issuer.clone(),
            (None, _) => self.account.clone(),
        }
    }

    /// The text a search query is matched against.
    fn haystack(&self) -> String {
        let mut text = self.issuer.clone().unwrap_or_default();
        text.push('\u{1}');
        text.push_str(&self.account);
        if let Some(note) = &self.note {
            text.push('\u{1}');
            text.push_str(note);
        }
        text.to_lowercase()
    }

    /// The code for the step containing `now`.
    pub fn code_at(&self, now_secs: u64) -> Result<String> {
        self.totp.code_at(&self.secret, now_secs)
    }

    /// Re-exports the account as an `otpauth://` URI.
    pub fn to_uri(&self) -> OtpauthUri {
        OtpauthUri {
            issuer: self.issuer.clone(),
            account: self.account.clone(),
            secret: self.secret.clone(),
            params: self.totp,
        }
    }
}

impl From<OtpauthUri> for Account {
    fn from(uri: OtpauthUri) -> Self {
        Self {
            issuer: uri.issuer,
            account: uri.account,
            secret: uri.secret,
            totp: uri.params,
            note: None,
        }
    }
}

/// One record in the vault: either an account or the tombstone that replaced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    /// Last modification, used by [`Vault::merge`].
    pub updated_at: Millis,
    /// Position in the manually sorted list.
    #[serde(default)]
    pub order: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub deleted: bool,
    /// `None` exactly when `deleted` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<Account>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl Entry {
    /// Decides which of two versions of the same entry survives a merge.
    ///
    /// Later modification wins. On an exact tie a tombstone beats a live
    /// entry — a delete that raced with an edit should not come back — and
    /// two live versions are broken by comparing their serialised form, so
    /// that the outcome does not depend on which side was called the local
    /// one.
    fn supersedes(&self, other: &Self) -> bool {
        match self.updated_at.cmp(&other.updated_at) {
            core::cmp::Ordering::Greater => true,
            core::cmp::Ordering::Less => false,
            core::cmp::Ordering::Equal => match (self.deleted, other.deleted) {
                (true, false) => true,
                (false, true) => false,
                _ => fingerprint(self) < fingerprint(other),
            },
        }
    }
}

/// A stable fingerprint of a value's canonical JSON.
///
/// Used wherever two records have to be compared or grouped deterministically.
/// Hashing rather than keeping the JSON means no extra plaintext copy of a
/// secret lingers in memory for the life of a merge.
fn fingerprint<T: serde::Serialize>(value: &T) -> [u8; 32] {
    let mut json = serde_json::to_string(value).unwrap_or_default();
    let digest = Sha256::digest(json.as_bytes());
    json.zeroize();
    digest.into()
}

/// How the list is ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortMode {
    /// The user's drag order.
    #[default]
    Manual,
    /// Alphabetical by issuer, then account.
    IssuerAsc,
}

/// App-lock settings (spec §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockSettings {
    pub biometric_enabled: bool,
    /// Seconds in the background before the app requires unlocking again.
    pub background_timeout_secs: u32,
    /// The PIN fallback, if the user set one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<PinVerifier>,
}

impl Default for LockSettings {
    fn default() -> Self {
        Self {
            biometric_enabled: true,
            background_timeout_secs: DEFAULT_BACKGROUND_TIMEOUT_SECS,
            pin: None,
        }
    }
}

/// Where a copy of the vault is synced to.
///
/// Several can be enabled at once: the local vault is the hub, and each
/// target is reconciled against it independently. That works because the
/// merge rule is commutative and idempotent, so the order the targets are
/// synced in does not change where they all end up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncTargetKind {
    /// A folder the OS already syncs: iCloud Drive, Google Drive, OneDrive.
    Folder,
    /// A file in a GitHub repository, over the API.
    GitHub,
    /// A file in a GitLab repository, over the API.
    GitLab,
    /// A self-hosted sync server, which stores ciphertext and nothing else.
    Server,
}

/// One configured sync target.
///
/// These travel with the vault, so adding a target on one device offers it on
/// the others. Credentials never travel: the token or password for a target
/// stays in each device's own secure store, and a device without them simply
/// cannot sync that target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncTarget {
    pub id: Uuid,
    pub kind: SyncTargetKind,
    /// What the user called it, e.g. "iCloud Drive" or "work GitHub".
    pub label: String,
    /// Where it is: a folder path, `owner/repo/branch`, or a base URL.
    pub location: String,
    /// The per-target switch. A disabled target is neither read nor written.
    pub enabled: bool,
}

/// Settings travel with the vault so they survive a restore, and merge as one
/// unit by their own modification time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub updated_at: Millis,
    #[serde(default)]
    pub lock: LockSettings,
    pub clipboard_clear_secs: u32,
    #[serde(default)]
    pub sort: SortMode,
    /// Configured sync targets, any number of which may be enabled.
    #[serde(default)]
    pub sync: Vec<SyncTarget>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            updated_at: 0,
            lock: LockSettings::default(),
            clipboard_clear_secs: DEFAULT_CLIPBOARD_CLEAR_SECS,
            sort: SortMode::default(),
            sync: Vec::new(),
        }
    }
}

/// What a merge did, for the UI to report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
    pub unchanged: usize,
    /// Entries collapsed by [`Vault::dedupe`] because another entry described
    /// exactly the same account.
    pub deduped: usize,
    pub settings_updated: bool,
    /// Whether the document ended up different from how it started.
    ///
    /// This is not implied by the counters: a duplicate arriving from another
    /// device is reported in `deduped` but leaves the document as it was.
    pub changed: bool,
}

impl MergeReport {
    /// Whether the merge left the document exactly as it was.
    pub fn is_empty(&self) -> bool {
        !self.changed
    }
}

/// The whole document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub format: u32,
    #[serde(default)]
    pub settings: Settings,
    /// Accounts and tombstones, kept sorted by id.
    ///
    /// One canonical order means a vault that has been through a save, a
    /// backup or a merge compares equal to the one it came from, and that two
    /// devices holding the same accounts write byte-identical files. Display
    /// order is a separate thing: see [`Vault::visible`].
    pub entries: Vec<Entry>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            format: VAULT_FORMAT,
            settings: Settings::default(),
            entries: Vec::new(),
        }
    }
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    // --- reading ---------------------------------------------------------

    /// Live entries in display order.
    pub fn visible(&self) -> Vec<&Entry> {
        let mut entries: Vec<&Entry> = self.entries.iter().filter(|entry| !entry.deleted).collect();
        match self.settings.sort {
            SortMode::Manual => entries.sort_by(|a, b| {
                a.order
                    .cmp(&b.order)
                    .then_with(|| sort_key(a).cmp(&sort_key(b)))
            }),
            SortMode::IssuerAsc => entries.sort_by_key(|entry| sort_key(entry)),
        }
        entries
    }

    /// Live entries matching `query`, case-insensitively, in display order.
    ///
    /// An empty or whitespace query matches everything, so a search box that
    /// has been cleared shows the full list.
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return self.visible();
        }
        self.visible()
            .into_iter()
            .filter(|entry| {
                entry
                    .account
                    .as_ref()
                    .is_some_and(|account| account.haystack().contains(&needle))
            })
            .collect()
    }

    /// The id of a live entry describing exactly the same account, if any.
    ///
    /// Every field has to match, the note included: two entries that differ
    /// at all are two accounts as far as this is concerned.
    pub fn find_duplicate(&self, account: &Account) -> Option<Uuid> {
        self.entries
            .iter()
            .find(|entry| entry.account.as_ref() == Some(account))
            .map(|entry| entry.id)
    }

    pub fn get(&self, id: Uuid) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.id == id && !entry.deleted)
    }

    /// Number of live accounts.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|entry| !entry.deleted).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The code for one account at `now_secs`.
    pub fn code_at(&self, id: Uuid, now_secs: u64) -> Result<String> {
        self.get(id)
            .and_then(|entry| entry.account.as_ref())
            .ok_or(Error::NoSuchAccount)?
            .code_at(now_secs)
    }

    // --- writing ---------------------------------------------------------

    /// Adds an account and returns its id.
    ///
    /// If a live entry already describes exactly the same account — every
    /// field equal — nothing is added and that entry's id comes back:
    /// scanning the same QR code twice should not produce two rows. Use
    /// [`Vault::find_duplicate`] first when the UI wants to say so.
    pub fn add(&mut self, account: impl Into<Account>, now: Millis) -> Uuid {
        let account = account.into();
        if let Some(existing) = self.find_duplicate(&account) {
            return existing;
        }

        let id = Uuid::new_v4();
        let order = self
            .entries
            .iter()
            .map(|entry| entry.order)
            .max()
            .map_or(0, |max| max + 1);
        self.entries.push(Entry {
            id,
            updated_at: now,
            order,
            deleted: false,
            account: Some(account),
        });
        self.normalize();
        id
    }

    /// Edits an account in place, stamping it as modified.
    pub fn update<F>(&mut self, id: Uuid, now: Millis, edit: F) -> Result<()>
    where
        F: FnOnce(&mut Account),
    {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == id && !entry.deleted)
            .ok_or(Error::NoSuchAccount)?;
        edit(entry.account.as_mut().ok_or(Error::NoSuchAccount)?);
        entry.updated_at = now;
        Ok(())
    }

    /// Replaces an account with a tombstone, dropping (and so wiping) the
    /// secret. The tombstone has to stay: without it, the next sync with a
    /// device that still has the account would bring it back.
    pub fn delete(&mut self, id: Uuid, now: Millis) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == id && !entry.deleted)
            .ok_or(Error::NoSuchAccount)?;
        entry.account = None;
        entry.deleted = true;
        entry.updated_at = now;
        Ok(())
    }

    /// Applies a drag-and-drop order. Ids not listed keep their position
    /// after the ones that are.
    pub fn reorder(&mut self, ordered_ids: &[Uuid], now: Millis) {
        let positions: BTreeMap<Uuid, i64> = ordered_ids
            .iter()
            .enumerate()
            .map(|(index, id)| (*id, index as i64))
            .collect();
        let tail = ordered_ids.len() as i64;

        for entry in &mut self.entries {
            if entry.deleted {
                continue;
            }
            let order = positions
                .get(&entry.id)
                .copied()
                .unwrap_or(tail + entry.order);
            if entry.order != order {
                entry.order = order;
                entry.updated_at = now;
            }
        }
    }

    /// Replaces the settings, stamping them as modified.
    pub fn set_settings(&mut self, settings: Settings, now: Millis) {
        self.settings = Settings {
            updated_at: now,
            ..settings
        };
    }

    // --- merging ---------------------------------------------------------

    /// Merges `other` into this vault, entry by entry.
    ///
    /// Exact duplicates are collapsed afterwards (see [`Vault::dedupe`]), so
    /// two devices that each scanned the same QR code end up with one row.
    pub fn merge(&mut self, other: Vault) -> MergeReport {
        let before = self.clone();
        self.absorb(other);
        let deduped = self.dedupe();

        let mut report = self.report_against(&before);
        report.deduped = deduped;
        report
    }

    /// Takes in another copy's entries and settings, without deduping or
    /// reporting.
    ///
    /// Separate from [`Vault::merge`] so that syncing against several targets
    /// at once can absorb each of them and then dedupe and report once, for
    /// the whole round rather than per target.
    pub(crate) fn absorb(&mut self, other: Vault) {
        let mut index: BTreeMap<Uuid, usize> = self
            .entries
            .iter()
            .enumerate()
            .map(|(position, entry)| (entry.id, position))
            .collect();

        for incoming in other.entries {
            match index.get(&incoming.id).copied() {
                None => {
                    // A tombstone for something we never had is kept too, or
                    // a third device would re-add the account next round.
                    index.insert(incoming.id, self.entries.len());
                    self.entries.push(incoming);
                }
                Some(position) => {
                    if incoming.supersedes(&self.entries[position]) {
                        self.entries[position] = incoming;
                    }
                }
            }
        }

        if other.settings.updated_at > self.settings.updated_at {
            self.settings = other.settings;
        }
        self.normalize();
    }

    /// Counts how this vault differs from `before`, the way a merge reports it.
    ///
    /// Everything but `deduped`, which a diff cannot tell apart from an entry
    /// that simply went away; the caller sets it.
    pub fn report_against(&self, before: &Vault) -> MergeReport {
        let previous: BTreeMap<Uuid, [u8; 32]> = before
            .entries
            .iter()
            .map(|entry| (entry.id, fingerprint(entry)))
            .collect();

        let mut report = MergeReport {
            settings_updated: self.settings.updated_at > before.settings.updated_at,
            ..MergeReport::default()
        };
        for entry in &self.entries {
            match previous.get(&entry.id) {
                None => {
                    if !entry.deleted {
                        report.added += 1;
                    }
                }
                Some(before) if *before == fingerprint(entry) => report.unchanged += 1,
                Some(_) if entry.deleted => report.deleted += 1,
                Some(_) => report.updated += 1,
            }
        }

        let surviving: BTreeSet<Uuid> = self.entries.iter().map(|entry| entry.id).collect();
        let dropped = previous.keys().filter(|id| !surviving.contains(id)).count();
        report.changed = report.settings_updated
            || dropped > 0
            || report.added + report.updated + report.deleted > 0;

        report
    }

    /// Drops tombstones older than `retain_ms`, returning how many went.
    pub fn prune_tombstones(&mut self, now: Millis, retain_ms: Millis) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|entry| !(entry.deleted && entry.updated_at < now - retain_ms));
        before - self.entries.len()
    }

    /// Collapses live entries that describe exactly the same account,
    /// keeping the one with the smallest id. Returns how many went.
    ///
    /// Two devices scanning the same QR code each mint their own UUID, so a
    /// merge would otherwise leave the user with two identical rows and no
    /// way to tell which is which. Keeping the smallest id is arbitrary, but
    /// it is the same choice on every device, so they all converge on it
    /// without having to record the decision anywhere.
    ///
    /// Only exact duplicates go. An entry that differs in any field — a note
    /// added on one device, a different period — is a different account here,
    /// and is left for the user to deal with.
    pub fn dedupe(&mut self) -> usize {
        self.normalize();

        let mut seen: BTreeMap<[u8; 32], Uuid> = BTreeMap::new();
        let mut doomed: BTreeSet<Uuid> = BTreeSet::new();

        // `entries` is sorted by id, so the first of a group is the one kept.
        for entry in &self.entries {
            let Some(account) = &entry.account else {
                continue;
            };
            let key = fingerprint(account);
            match seen.get(&key) {
                Some(_) => {
                    doomed.insert(entry.id);
                }
                None => {
                    seen.insert(key, entry.id);
                }
            }
        }

        self.entries.retain(|entry| !doomed.contains(&entry.id));
        doomed.len()
    }

    /// Restores the canonical entry order after a mutation.
    fn normalize(&mut self) {
        self.entries.sort_by_key(|entry| entry.id);
    }

    // --- serialising -----------------------------------------------------

    /// The document as canonical JSON.
    ///
    /// `entries` is normally already in canonical order; it is sorted again
    /// here because the field is public and a caller may have appended to it.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut canonical = self.clone();
        canonical.normalize();
        serde_json::to_vec(&canonical).map_err(|_| Error::MalformedVault)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut vault: Vault = serde_json::from_slice(bytes).map_err(|_| Error::MalformedVault)?;
        if vault.format > VAULT_FORMAT {
            return Err(Error::UnsupportedFormat {
                found: u8::try_from(vault.format).unwrap_or(u8::MAX),
                supported: u8::try_from(VAULT_FORMAT).unwrap_or(u8::MAX),
            });
        }
        for entry in &vault.entries {
            // A live entry without an account, or a tombstone with one, would
            // make `visible()` and `merge()` disagree about what exists.
            if entry.deleted == entry.account.is_some() {
                return Err(Error::MalformedVault);
            }
            if let Some(account) = &entry.account {
                account.totp.validate()?;
            }
        }
        vault.normalize();
        Ok(vault)
    }

    /// Encrypts the vault with the data key from the platform secure store.
    pub fn seal(&self, key: &DataKey) -> Result<Vec<u8>> {
        container::seal_with_key(Kind::Vault, key, &self.to_bytes()?)
    }

    /// Decrypts a vault file.
    pub fn open(key: &DataKey, bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(&container::open_with_key(Kind::Vault, key, bytes)?)
    }
}

/// Alphabetical key: issuer, then account, case-insensitive.
fn sort_key(entry: &Entry) -> (String, String) {
    match &entry.account {
        Some(account) => (
            account.issuer.clone().unwrap_or_default().to_lowercase(),
            account.account.to_lowercase(),
        ),
        None => (String::new(), String::new()),
    }
}
