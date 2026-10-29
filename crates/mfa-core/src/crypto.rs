//! Cryptographic primitives: XChaCha20-Poly1305 for data, Argon2id for
//! password-derived keys.
//!
//! Nothing here chooses *what* to encrypt; that is [`crate::container`]'s job.

use core::fmt;

use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Key length for XChaCha20-Poly1305.
pub const KEY_LEN: usize = 32;
/// XChaCha20's extended nonce, long enough to pick at random per write.
pub const NONCE_LEN: usize = 24;
/// Salt length for Argon2id.
pub const SALT_LEN: usize = 16;

/// A 32-byte symmetric key, wiped on drop.
///
/// Used both for the vault's randomly generated data key and for keys derived
/// from a password.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; KEY_LEN]);

impl DataKey {
    /// A fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Fails unless the slice is exactly [`KEY_LEN`] bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::CorruptFile)?;
        Ok(Self(bytes))
    }

    /// The raw key. Named to make every use site obvious in review.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey(<redacted, 32 bytes>)")
    }
}

/// Argon2id cost parameters, recorded in every file header so a file written
/// today still opens after we raise the defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 64 MiB / 3 passes / 1 lane, on every device.
    ///
    /// There is deliberately no lighter preset for older phones: this one
    /// password protects the backup file and the sync key on every target, so
    /// a device that found it slow would be lowering the cost of attacking all
    /// of them. A slow unlock on an old phone is the better trade.
    fn default() -> Self {
        Self {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// Rejects parameters too weak to protect a backup password.
    pub fn validate(&self) -> Result<()> {
        if self.m_cost < 8 * 1024 || self.t_cost == 0 || self.p_cost == 0 {
            return Err(Error::KeyDerivationFailed);
        }
        Ok(())
    }
}

/// Fills `out` with cryptographically secure random bytes.
pub fn random_bytes(out: &mut [u8]) {
    OsRng.fill_bytes(out);
}

/// A fresh random salt.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    random_bytes(&mut salt);
    salt
}

/// A fresh random nonce. Never reuse one with the same key.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce);
    nonce
}

/// Derives a key from a password with Argon2id.
///
/// The caller supplies the salt and records `params` alongside the ciphertext;
/// otherwise the same password cannot be used to re-derive the key later.
pub fn derive_key(password: &[u8], salt: &[u8], params: &KdfParams) -> Result<DataKey> {
    params.validate()?;

    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| Error::KeyDerivationFailed)?;
    let argon = Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut key)
        .map_err(|_| Error::KeyDerivationFailed)?;

    let derived = DataKey::from_bytes(key);
    key.zeroize();
    Ok(derived)
}

/// Encrypts `plaintext`, authenticating `aad` along with it.
pub fn encrypt(
    key: &DataKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(key.expose().into())
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // Encryption only fails if the message is absurdly large.
        .map_err(|_| Error::CorruptFile)
}

/// Decrypts `ciphertext`, requiring `aad` to match what was sealed.
///
/// Returns `None` when authentication fails, so the caller decides whether
/// that means "wrong password" or "altered file".
pub fn decrypt(
    key: &DataKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    XChaCha20Poly1305::new(key.expose().into())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}
