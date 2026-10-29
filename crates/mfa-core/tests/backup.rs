//! Encrypted backup export and import (spec §1, §5).

mod common;

use common::{account, replace_bytes, test_kdf};
use mfa_core::crypto::KdfParams;
use mfa_core::vault::Vault;
use mfa_core::{backup, Error};

const T0: i64 = 1_700_000_000_000;
const PASSWORD: &str = "correct horse battery staple";

fn populated() -> Vault {
    let mut vault = Vault::new();
    vault.add(account("GitHub", "alice@example.com"), T0);
    let id = vault.add(account("Bank", "carol"), T0 + 1_000);
    vault
        .update(id, T0 + 2_000, |account| {
            account.note = Some("savings".to_owned())
        })
        .unwrap();
    let doomed = vault.add(account("Gone", "dave"), T0 + 3_000);
    vault.delete(doomed, T0 + 4_000).unwrap();
    vault
}

#[test]
fn a_backup_round_trips_with_the_right_password() {
    let vault = populated();
    let file = backup::export(&vault, PASSWORD, &test_kdf()).unwrap();

    let restored = backup::import(&file, PASSWORD).unwrap();
    assert_eq!(restored, vault);
    // Tombstones survive the trip, or a restore would resurrect accounts the
    // user deleted.
    assert_eq!(restored.entries.len(), 3);
    assert_eq!(restored.len(), 2);
}

#[test]
fn a_backup_restores_identically_on_another_platform() {
    // Spec §5: export on platform A, import on platform B, same contents.
    // Nothing here is platform-dependent by construction, so what this really
    // pins down is that the document bytes are canonical.
    let vault = populated();
    let file = backup::export(&vault, PASSWORD, &test_kdf()).unwrap();

    let restored = backup::import(&file, PASSWORD).unwrap();
    assert_eq!(restored.to_bytes().unwrap(), vault.to_bytes().unwrap());

    // Two exports of the same vault differ (fresh salt and nonce) but restore
    // to the same document.
    let again = backup::export(&vault, PASSWORD, &test_kdf()).unwrap();
    assert_ne!(again, file);
    assert_eq!(
        backup::import(&again, PASSWORD)
            .unwrap()
            .to_bytes()
            .unwrap(),
        restored.to_bytes().unwrap()
    );
}

#[test]
fn the_wrong_password_is_reported_clearly_and_changes_nothing() {
    // Spec §5: "a wrong password reports clearly and does not damage existing
    // data".
    let file = backup::export(&populated(), PASSWORD, &test_kdf()).unwrap();

    let mut existing = Vault::new();
    existing.add(account("Keep", "me"), T0);
    let before = existing.to_bytes().unwrap();

    let error = backup::import_into(&mut existing, &file, "wrong password").unwrap_err();
    assert!(matches!(error, Error::WrongPassword), "got {error:?}");
    assert!(error.to_string().contains("password"));
    assert_eq!(
        existing.to_bytes().unwrap(),
        before,
        "the existing vault must be untouched"
    );
}

#[test]
fn a_truncated_backup_changes_nothing_either() {
    let file = backup::export(&populated(), PASSWORD, &test_kdf()).unwrap();

    let mut existing = Vault::new();
    existing.add(account("Keep", "me"), T0);
    let before = existing.to_bytes().unwrap();

    assert!(backup::import_into(&mut existing, &file[..file.len() / 2], PASSWORD).is_err());
    assert_eq!(existing.to_bytes().unwrap(), before);
}

#[test]
fn importing_merges_rather_than_replaces() {
    let file = backup::export(&populated(), PASSWORD, &test_kdf()).unwrap();

    let mut existing = Vault::new();
    existing.add(account("Local Only", "me"), T0 + 10_000);

    let report = backup::import_into(&mut existing, &file, PASSWORD).unwrap();
    assert_eq!(report.added, 2);
    assert_eq!(existing.len(), 3, "the local account is still there");
}

#[test]
fn a_backup_says_what_it_needs_before_the_password_is_asked_for() {
    let kdf = test_kdf();
    let file = backup::export(&populated(), PASSWORD, &kdf).unwrap();

    let info = backup::inspect(&file).unwrap();
    assert_eq!(info.kdf, Some(kdf));
    assert_eq!(info.format, mfa_core::container::FORMAT_VERSION);
}

#[test]
fn weakening_the_recorded_kdf_cost_is_detected() {
    // The KDF parameters are authenticated, so an attacker cannot hand back a
    // file that makes the client derive the key cheaply and then brute-force
    // the password offline.
    let kdf = KdfParams {
        m_cost: 8192,
        t_cost: 1,
        p_cost: 1,
    };
    let file = backup::export(&populated(), PASSWORD, &kdf).unwrap();

    // Same length, so the header stays parseable.
    let weakened = replace_bytes(&file, br#""m_cost":8192"#, br#""m_cost":8193"#);
    assert!(backup::import(&weakened, PASSWORD).is_err());
}

#[test]
fn a_vault_file_is_not_accepted_as_a_backup() {
    let key = mfa_core::crypto::DataKey::generate();
    let sealed = populated().seal(&key).unwrap();

    assert!(backup::inspect(&sealed).is_err());
    let error = backup::import(&sealed, PASSWORD).unwrap_err();
    assert!(
        matches!(error, Error::WrongFileKind { expected: "backup" }),
        "got {error:?}"
    );
}

#[test]
fn a_password_too_short_to_protect_a_cloud_file_is_refused() {
    let error = backup::export(&populated(), "short", &test_kdf()).unwrap_err();
    assert!(error.to_string().contains("password"), "got {error}");

    // At the limit it is accepted.
    assert!(backup::export(&populated(), "12345678", &test_kdf()).is_ok());
}

#[test]
fn an_empty_vault_can_be_backed_up() {
    let file = backup::export(&Vault::new(), PASSWORD, &test_kdf()).unwrap();
    assert!(backup::import(&file, PASSWORD).unwrap().is_empty());
}
