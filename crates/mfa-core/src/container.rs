//! The envelope both the vault file and the backup file use.
//!
//! ```text
//! 0..8    magic: "MFAVAULT" or "MFABACKP"
//! 8       format version (u8)
//! 9..11   header length (u16, little-endian)
//! 11..    header, JSON: cipher, nonce, and the KDF parameters if any
//! then    XChaCha20-Poly1305 ciphertext and tag
//! ```
//!
//! The AAD is every byte before the ciphertext, so the magic, the version and
//! the recorded KDF cost are all authenticated: an attacker cannot talk a
//! client into deriving a key with cheaper parameters, and a vault file cannot
//! be passed off as a backup file.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{self, DataKey, KdfParams, NONCE_LEN};
use crate::error::{Error, Result};

/// The format version this build writes.
pub const FORMAT_VERSION: u8 = 1;
/// The newest format version this build can read.
pub const SUPPORTED_FORMAT: u8 = 1;

const CIPHER_NAME: &str = "xchacha20poly1305";
const KDF_NAME: &str = "argon2id";
const PREAMBLE_LEN: usize = 11;

/// Which kind of file an envelope holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The local vault, encrypted with the key in the platform's secure store.
    Vault,
    /// An export, encrypted with a password-derived key.
    Backup,
    /// A file in the user's own cloud folder, encrypted with the sync key.
    Sync,
}

impl Kind {
    fn magic(self) -> &'static [u8; 8] {
        match self {
            Kind::Vault => b"MFAVAULT",
            Kind::Backup => b"MFABACKP",
            Kind::Sync => b"MFASYNC1",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Vault => "vault",
            Kind::Backup => "backup",
            Kind::Sync => "sync",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    cipher: String,
    /// Base64, 24 bytes.
    nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfHeader>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfHeader {
    id: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    /// Base64, 16 bytes.
    salt: String,
}

/// What can be learnt about a file without the key: enough to tell the user
/// what they are holding and to show a progress spinner sized to the KDF cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub kind: Kind,
    pub format: u8,
    /// `None` for a vault file, whose key lives in the platform secure store.
    pub kdf: Option<KdfParams>,
}

/// Seals `plaintext` with a key that is already in hand (the vault case).
pub fn seal_with_key(kind: Kind, key: &DataKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    seal(kind, key, None, plaintext)
}

/// Derives a key from `password` and seals `plaintext` with it.
pub fn seal_with_password(
    kind: Kind,
    password: &str,
    params: &KdfParams,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let salt = crypto::random_salt();
    let key = crypto::derive_key(password.as_bytes(), &salt, params)?;
    seal(kind, &key, Some((*params, salt)), plaintext)
}

fn seal(
    kind: Kind,
    key: &DataKey,
    kdf: Option<(KdfParams, [u8; crypto::SALT_LEN])>,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let nonce = crypto::random_nonce();
    let header = Header {
        cipher: CIPHER_NAME.to_owned(),
        nonce: BASE64.encode(nonce),
        kdf: kdf.map(|(params, salt)| KdfHeader {
            id: KDF_NAME.to_owned(),
            m_cost: params.m_cost,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            salt: BASE64.encode(salt),
        }),
    };
    let header_json = serde_json::to_vec(&header).map_err(|_| Error::CorruptFile)?;
    let header_len = u16::try_from(header_json.len()).map_err(|_| Error::CorruptFile)?;

    let mut file = Vec::with_capacity(PREAMBLE_LEN + header_json.len() + plaintext.len() + 16);
    file.extend_from_slice(kind.magic());
    file.push(FORMAT_VERSION);
    file.extend_from_slice(&header_len.to_le_bytes());
    file.extend_from_slice(&header_json);

    // Everything written so far is the AAD.
    let ciphertext = crypto::encrypt(key, &nonce, &file, plaintext)?;
    file.extend_from_slice(&ciphertext);
    Ok(file)
}

/// Reads what a file declares about itself, without needing the key.
pub fn inspect(bytes: &[u8]) -> Result<Info> {
    let parsed = parse(bytes)?;
    Ok(Info {
        kind: parsed.kind,
        format: parsed.format,
        kdf: parsed.header.kdf.as_ref().map(|kdf| KdfParams {
            m_cost: kdf.m_cost,
            t_cost: kdf.t_cost,
            p_cost: kdf.p_cost,
        }),
    })
}

/// Opens a file with a key already in hand (the vault case).
pub fn open_with_key(kind: Kind, key: &DataKey, bytes: &[u8]) -> Result<Vec<u8>> {
    let parsed = parse(bytes)?;
    parsed.require_kind(kind)?;
    parsed.decrypt(key).ok_or(Error::DecryptionFailed)
}

/// Opens a password-protected file.
///
/// A wrong password and an altered file are indistinguishable at this layer —
/// both are an authentication failure — and are both reported as
/// [`Error::WrongPassword`], which is the overwhelmingly likely cause and the
/// one the user can do something about.
pub fn open_with_password(kind: Kind, password: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let parsed = parse(bytes)?;
    parsed.require_kind(kind)?;

    let kdf = parsed.header.kdf.as_ref().ok_or(Error::CorruptFile)?;
    if kdf.id != KDF_NAME {
        return Err(Error::UnsupportedKdf(kdf.id.clone()));
    }
    let salt = BASE64.decode(&kdf.salt).map_err(|_| Error::CorruptFile)?;
    let params = KdfParams {
        m_cost: kdf.m_cost,
        t_cost: kdf.t_cost,
        p_cost: kdf.p_cost,
    };

    let key = crypto::derive_key(password.as_bytes(), &salt, &params)?;
    parsed.decrypt(&key).ok_or(Error::WrongPassword)
}

struct Parsed<'a> {
    kind: Kind,
    format: u8,
    header: Header,
    /// Magic, version, header length and header JSON: the AAD.
    aad: &'a [u8],
    ciphertext: &'a [u8],
}

impl Parsed<'_> {
    fn require_kind(&self, expected: Kind) -> Result<()> {
        if self.kind == expected {
            Ok(())
        } else {
            Err(Error::WrongFileKind {
                expected: expected.name(),
            })
        }
    }

    fn decrypt(&self, key: &DataKey) -> Option<Vec<u8>> {
        let mut nonce_bytes = BASE64.decode(&self.header.nonce).ok()?;
        let nonce: [u8; NONCE_LEN] = nonce_bytes.as_slice().try_into().ok()?;
        nonce_bytes.zeroize();
        crypto::decrypt(key, &nonce, self.aad, self.ciphertext)
    }
}

fn parse(bytes: &[u8]) -> Result<Parsed<'_>> {
    let preamble = bytes.get(..PREAMBLE_LEN).ok_or(Error::CorruptFile)?;

    let magic: &[u8; 8] = preamble[..8]
        .try_into()
        .expect("8 bytes of an 11-byte slice");
    let kind = if magic == Kind::Vault.magic() {
        Kind::Vault
    } else if magic == Kind::Backup.magic() {
        Kind::Backup
    } else if magic == Kind::Sync.magic() {
        Kind::Sync
    } else {
        // The caller knows which kind it asked for; name that one.
        return Err(Error::CorruptFile);
    };

    let format = preamble[8];
    if format > SUPPORTED_FORMAT {
        return Err(Error::UnsupportedFormat {
            found: format,
            supported: SUPPORTED_FORMAT,
        });
    }

    let header_len = usize::from(u16::from_le_bytes([preamble[9], preamble[10]]));
    let header_end = PREAMBLE_LEN + header_len;
    let header_json = bytes
        .get(PREAMBLE_LEN..header_end)
        .ok_or(Error::CorruptFile)?;
    let header: Header = serde_json::from_slice(header_json).map_err(|_| Error::CorruptFile)?;

    if header.cipher != CIPHER_NAME {
        return Err(Error::UnsupportedCipher(header.cipher));
    }

    let ciphertext = bytes.get(header_end..).ok_or(Error::CorruptFile)?;
    if ciphertext.len() <= 16 {
        // Nothing but a tag, or not even that.
        return Err(Error::CorruptFile);
    }

    Ok(Parsed {
        kind,
        format,
        header,
        aad: &bytes[..header_end],
        ciphertext,
    })
}
