//! Helpers shared by the vault, backup and sync tests.
//!
//! Each integration test is its own crate and includes this module whole, so
//! a helper only one of them needs looks unused in the others.
#![allow(dead_code)]

use mfa_core::crypto::KdfParams;
use mfa_core::vault::Account;
use mfa_core::OtpauthUri;

/// Argon2id at the lowest parameters the core accepts.
///
/// Tests exercise the format, not the cost; the shipping defaults
/// (`KdfParams::default()`) would make this suite take minutes.
pub fn test_kdf() -> KdfParams {
    KdfParams {
        m_cost: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

/// An account with a distinct secret per `seed` character.
pub fn account(issuer: &str, name: &str) -> Account {
    OtpauthUri::parse(&format!(
        "otpauth://totp/{issuer}:{name}?secret=JBSWY3DPEHPK3PXP&issuer={issuer}"
    ))
    .expect("the test URI is well formed")
    .into()
}

/// Replaces the first occurrence of `needle` in `bytes`. Panics if absent, so
/// a test cannot silently stop testing what it meant to.
pub fn replace_bytes(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(
        needle.len(),
        replacement.len(),
        "replacement must keep the length so the header stays parseable"
    );
    let at = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap_or_else(|| {
            panic!(
                "{:?} not found in the file",
                String::from_utf8_lossy(needle)
            )
        });

    let mut patched = bytes.to_vec();
    patched[at..at + needle.len()].copy_from_slice(replacement);
    patched
}
