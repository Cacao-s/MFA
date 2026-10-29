//! What each platform shell has to provide.
//!
//! The core is deliberately free of I/O, so these traits are the whole
//! contract between it and a platform. They are also the checklist the step-0
//! spike has to prove on all four platforms (see `spike/README.md`): if one of
//! these cannot be implemented on a platform, the technology choice is wrong
//! and no amount of core code will fix it.
//!
//! Each trait carries its own `Error` so a platform can surface its native
//! error type without the core depending on it.

use crate::crypto::DataKey;

/// The platform's secure storage: iOS/macOS Keychain, Android Keystore,
/// Windows DPAPI or Credential Manager, Linux Secret Service.
///
/// This is where the vault's data key lives, and it is the one thing that must
/// not be emulated with a file: the whole security model (spec §4) rests on
/// the key being held by the OS rather than by us.
pub trait SecureStore {
    type Error;

    /// The stored data key, or `None` on a fresh install.
    fn data_key(&self) -> Result<Option<DataKey>, Self::Error>;

    /// Stores the data key, replacing any existing one.
    fn put_data_key(&self, key: &DataKey) -> Result<(), Self::Error>;

    /// Removes the data key, which makes the vault file unreadable. Used when
    /// the user resets the app.
    fn delete_data_key(&self) -> Result<(), Self::Error>;

    /// The sync key, when the device has joined a sync set.
    fn sync_key(&self) -> Result<Option<DataKey>, Self::Error>;

    fn put_sync_key(&self, key: &DataKey) -> Result<(), Self::Error>;
}

/// What biometric hardware is available right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricCapability {
    /// Face ID, Touch ID, Windows Hello, Android BiometricPrompt.
    Available,
    /// Hardware exists but the user has not enrolled.
    NotEnrolled,
    /// No hardware, or the platform does not expose it.
    Unavailable,
}

/// Why an unlock prompt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    Succeeded,
    /// The user dismissed the prompt.
    Cancelled,
    /// Biometrics failed or are locked out; offer the PIN instead.
    Failed,
}

/// The app lock's biometric gate (spec §4).
pub trait BiometricAuth {
    type Error;

    fn capability(&self) -> BiometricCapability;

    /// Prompts the user. `reason` is shown by the OS and must be localised.
    fn authenticate(&self, reason: &str) -> Result<AuthOutcome, Self::Error>;
}

/// Reading a QR code from the camera (mobile) or from an image or screen grab
/// (desktop — see [`crate::qr`] for the decoding itself).
pub trait QrScanner {
    type Error;

    /// The payloads of every QR code found, as text.
    fn scan(&self) -> Result<Vec<String>, Self::Error>;
}

/// Where the encrypted vault file lives on this platform.
pub trait VaultStorage {
    type Error;

    /// The vault file, or `None` on a fresh install.
    fn load(&self) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Writes the vault file. Implementations must write atomically — to a
    /// temporary file, then rename — so a crash mid-write cannot leave a
    /// vault that no longer decrypts.
    fn store(&self, bytes: &[u8]) -> Result<(), Self::Error>;
}

/// The clipboard, with the auto-clear spec §4 asks for.
pub trait Clipboard {
    type Error;

    /// Copies `text`, scheduling a clear after `clear_after_secs` where the
    /// platform allows it. Implementations that cannot clear the clipboard
    /// must say so by returning `false`, so the UI can stop promising it.
    fn copy(&self, text: &str, clear_after_secs: u32) -> Result<bool, Self::Error>;
}

/// A file as the provider handed it over, with the revision it was at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFile<R> {
    pub bytes: Vec<u8>,
    pub revision: R,
}

/// One place a copy of the vault is kept (spec §3).
///
/// All four kinds of target are this one trait, because they differ only in
/// how bytes move:
///
/// - a folder the OS already syncs — iCloud Drive, Google Drive, OneDrive;
/// - a file in a GitHub repository, where the revision is the blob `sha`;
/// - a file in a GitLab repository, where it is `last_commit_id`;
/// - a self-hosted sync server, where it is whatever the server returns, an
///   ETag being the obvious choice.
///
/// A server implementation needs credentials, as the Git ones do; they belong
/// in the platform's secure store next to the sync key, never in the vault.
/// The server stores ciphertext and nothing else, so it is no more trusted
/// than a cloud drive — which is the point of self-hosting being optional
/// rather than special.
///
/// `Revision` is whatever the target uses to detect a concurrent write.
/// A write must fail rather than clobber a revision we have not merged,
/// because the sync file is opaque ciphertext that no target can merge.
///
/// **The core never calls this.** [`crate::sync::reconcile_all`] takes and
/// returns bytes, so a shell is free to do its networking in its own idiom —
/// `URLSession`, coroutines, whatever — and this trait is here to say what
/// that code has to guarantee. Nothing in the core needs to become async for
/// it. `crates/mfa-sync-server/tests/end_to_end.rs` has the loop written out.
pub trait SyncProvider {
    type Error;
    type Revision: Clone + PartialEq;

    /// Downloads the file, or `None` if it is not there yet.
    fn fetch(&self, name: &str) -> Result<Option<RemoteFile<Self::Revision>>, Self::Error>;

    /// Uploads the file only if the remote is still at `expected`.
    ///
    /// Returns `None` when the revision moved, which tells the caller to
    /// fetch, merge and try again.
    fn put_if_unchanged(
        &self,
        name: &str,
        bytes: &[u8],
        expected: Option<&Self::Revision>,
    ) -> Result<Option<Self::Revision>, Self::Error>;
}
