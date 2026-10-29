//! Password-protected export and import (spec §1, §5).
//!
//! The file is a [`crate::container`] envelope keyed by Argon2id over the
//! user's backup password, so the same file opens on any platform. Import is a
//! pure function: it decrypts and parses before touching anything, which is
//! what makes "a wrong password must not damage existing data" true by
//! construction rather than by care.

use crate::container::{self, Kind};
use crate::crypto::KdfParams;
use crate::error::{Error, Result};
use crate::vault::{MergeReport, Vault};

/// Shortest backup password we will write a file for. A backup sits in a cloud
/// drive where it can be copied and attacked offline, so this floor matters
/// more than the app-lock PIN's.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Encrypts the vault for export.
pub fn export(vault: &Vault, password: &str, kdf: &KdfParams) -> Result<Vec<u8>> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(Error::InvalidParameter(
            format!("shorter than {MIN_PASSWORD_LEN} characters"),
            "password",
        ));
    }
    container::seal_with_password(Kind::Backup, password, kdf, &vault.to_bytes()?)
}

/// Decrypts and parses a backup file.
pub fn import(bytes: &[u8], password: &str) -> Result<Vault> {
    Vault::from_bytes(&container::open_with_password(
        Kind::Backup,
        password,
        bytes,
    )?)
}

/// What a backup declares about itself without the password: the format
/// version and the KDF cost, so the UI can warn before a slow derivation.
pub fn inspect(bytes: &[u8]) -> Result<container::Info> {
    let info = container::inspect(bytes)?;
    if info.kind != Kind::Backup {
        return Err(Error::WrongFileKind { expected: "backup" });
    }
    Ok(info)
}

/// Imports a backup into an existing vault, merging rather than replacing.
///
/// `target` is left untouched unless the whole file decrypted and parsed, so a
/// wrong password or a truncated file cannot leave a half-restored vault.
pub fn import_into(target: &mut Vault, bytes: &[u8], password: &str) -> Result<MergeReport> {
    let imported = import(bytes, password)?;
    Ok(target.merge(imported))
}
