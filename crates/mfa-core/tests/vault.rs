//! The vault document: editing, searching, sealing, and what it refuses.

mod common;

use common::{account, replace_bytes};
use mfa_core::crypto::DataKey;
use mfa_core::vault::{SortMode, Vault, VAULT_FORMAT};
use mfa_core::Error;

const T0: i64 = 1_700_000_000_000;

#[test]
fn an_added_account_is_visible_and_generates_codes() {
    let mut vault = Vault::new();
    let id = vault.add(account("Example", "alice"), T0);

    assert_eq!(vault.len(), 1);
    assert_eq!(vault.visible().len(), 1);
    assert_eq!(
        vault
            .get(id)
            .unwrap()
            .account
            .as_ref()
            .unwrap()
            .display_name(),
        "Example (alice)"
    );

    // Cross-checked against Python's hmac (tools/totp_ref.py) for the
    // JBSWY3DPEHPK3PXP secret at T=59.
    assert_eq!(vault.code_at(id, 59).unwrap(), "996554");
    assert_eq!(vault.code_at(id, 1_000_000_000).unwrap(), "949556");
}

#[test]
fn scanning_the_same_qr_code_twice_does_not_add_a_second_row() {
    let mut vault = Vault::new();
    let first = vault.add(account("Example", "alice"), T0);
    let again = vault.add(account("Example", "alice"), T0 + 5_000);

    assert_eq!(again, first, "the existing account comes back");
    assert_eq!(vault.len(), 1);

    // The UI can ask first, so it can say so rather than silently no-op.
    assert_eq!(
        vault.find_duplicate(&account("Example", "alice")),
        Some(first)
    );
    assert_eq!(vault.find_duplicate(&account("Example", "bob")), None);

    // An account that differs in any field is a different account.
    let mut with_note = account("Example", "alice");
    with_note.note = Some("work".to_owned());
    assert_eq!(vault.find_duplicate(&with_note), None);
    assert_ne!(vault.add(with_note, T0 + 6_000), first);
    assert_eq!(vault.len(), 2);
}

#[test]
fn a_deleted_account_can_be_added_again() {
    // The tombstone must not make the account un-addable: a user who deleted
    // it by mistake has to be able to scan the QR code again.
    let mut vault = Vault::new();
    let first = vault.add(account("Example", "alice"), T0);
    vault.delete(first, T0 + 1_000).unwrap();

    let second = vault.add(account("Example", "alice"), T0 + 2_000);
    assert_ne!(second, first);
    assert_eq!(vault.len(), 1);
}

#[test]
fn editing_an_account_stamps_it_as_modified() {
    let mut vault = Vault::new();
    let id = vault.add(account("Example", "alice"), T0);

    vault
        .update(id, T0 + 5_000, |account| {
            account.note = Some("work laptop".to_owned());
        })
        .unwrap();

    let entry = vault.get(id).unwrap();
    assert_eq!(entry.updated_at, T0 + 5_000);
    assert_eq!(
        entry.account.as_ref().unwrap().note.as_deref(),
        Some("work laptop")
    );
}

#[test]
fn deleting_leaves_a_tombstone_with_no_secret() {
    let mut vault = Vault::new();
    let id = vault.add(account("Example", "alice"), T0);
    vault.delete(id, T0 + 1_000).unwrap();

    assert_eq!(vault.len(), 0);
    assert!(vault.get(id).is_none());
    assert!(vault.visible().is_empty());

    // The record stays so that a later sync does not resurrect the account,
    // but the secret is gone from it.
    let tombstone = vault
        .entries
        .iter()
        .find(|entry| entry.id == id)
        .expect("the tombstone is kept");
    assert!(tombstone.deleted);
    assert!(tombstone.account.is_none());

    // And it cannot be deleted or edited twice.
    assert!(vault.delete(id, T0 + 2_000).is_err());
    assert!(vault.update(id, T0 + 2_000, |_| {}).is_err());
}

#[test]
fn search_matches_issuer_account_and_note_case_insensitively() {
    let mut vault = Vault::new();
    vault.add(account("GitHub", "alice@example.com"), T0);
    vault.add(account("Google", "bob@example.com"), T0);
    let id = vault.add(account("Bank", "carol"), T0);
    vault
        .update(id, T0, |account| account.note = Some("savings".to_owned()))
        .unwrap();

    let names = |results: Vec<&mfa_core::vault::Entry>| -> Vec<String> {
        results
            .iter()
            .map(|entry| entry.account.as_ref().unwrap().display_name())
            .collect()
    };

    assert_eq!(
        names(vault.search("git")),
        vec!["GitHub (alice@example.com)"]
    );
    assert_eq!(names(vault.search("GOO")), vec!["Google (bob@example.com)"]);
    assert_eq!(names(vault.search("savings")), vec!["Bank (carol)"]);
    assert_eq!(vault.search("bob").len(), 1);
    assert_eq!(vault.search("nothing here").len(), 0);
    // A cleared search box shows everything.
    assert_eq!(vault.search("   ").len(), 3);
}

#[test]
fn a_deleted_account_cannot_be_found_by_search() {
    let mut vault = Vault::new();
    let id = vault.add(account("GitHub", "alice"), T0);
    vault.delete(id, T0 + 1).unwrap();
    assert!(vault.search("github").is_empty());
}

#[test]
fn drag_order_is_kept_and_alphabetical_sort_ignores_it() {
    let mut vault = Vault::new();
    let github = vault.add(account("GitHub", "alice"), T0);
    let apple = vault.add(account("Apple", "bob"), T0);
    let zoom = vault.add(account("Zoom", "carol"), T0);

    vault.reorder(&[zoom, github, apple], T0 + 1_000);
    let order: Vec<_> = vault.visible().iter().map(|entry| entry.id).collect();
    assert_eq!(order, vec![zoom, github, apple]);

    // Reordering only stamps the entries that actually moved.
    assert_eq!(vault.get(github).unwrap().updated_at, T0 + 1_000);

    let mut settings = vault.settings.clone();
    settings.sort = SortMode::IssuerAsc;
    vault.set_settings(settings, T0 + 2_000);

    let order: Vec<_> = vault.visible().iter().map(|entry| entry.id).collect();
    assert_eq!(order, vec![apple, github, zoom]);
}

#[test]
fn the_document_serialises_the_same_whatever_order_its_entries_are_in() {
    // Spec §5: a backup written on one platform has to match one written on
    // another, so serialisation cannot depend on the order entries happen to
    // sit in memory. `entries` is a public field, so a caller can put them in
    // any order at all.
    let mut vault = Vault::new();
    vault.add(account("GitHub", "alice"), T0);
    vault.add(account("Zoom", "bob"), T0 + 1);
    let doomed = vault.add(account("Gone", "carol"), T0 + 2);
    vault.delete(doomed, T0 + 3).unwrap();

    let canonical = vault.to_bytes().unwrap();

    let mut shuffled = vault.clone();
    shuffled.entries.reverse();
    assert_eq!(shuffled.to_bytes().unwrap(), canonical);

    shuffled.entries.rotate_left(1);
    assert_eq!(shuffled.to_bytes().unwrap(), canonical);

    // And reading it back puts them in canonical order, so a round trip
    // compares equal to what went in.
    assert_eq!(Vault::from_bytes(&canonical).unwrap(), vault);
}

#[test]
fn a_sealed_vault_round_trips() {
    let key = DataKey::generate();
    let mut vault = Vault::new();
    vault.add(account("Example", "alice"), T0);

    let sealed = Vault::open(&key, &vault.seal(&key).unwrap()).unwrap();
    assert_eq!(sealed, vault);
    assert_eq!(sealed.format, VAULT_FORMAT);
}

#[test]
fn the_same_vault_never_seals_to_the_same_bytes_twice() {
    // Each write picks a fresh nonce; identical output would mean nonce reuse.
    let key = DataKey::generate();
    let vault = Vault::new();
    assert_ne!(vault.seal(&key).unwrap(), vault.seal(&key).unwrap());
}

#[test]
fn a_vault_does_not_open_with_the_wrong_key() {
    let vault = Vault::new();
    let sealed = vault.seal(&DataKey::generate()).unwrap();

    let error = Vault::open(&DataKey::generate(), &sealed).unwrap_err();
    assert!(matches!(error, Error::DecryptionFailed), "got {error:?}");
}

#[test]
fn tampering_with_a_sealed_vault_is_detected() {
    let key = DataKey::generate();
    let mut vault = Vault::new();
    vault.add(account("Example", "alice"), T0);
    let sealed = vault.seal(&key).unwrap();

    // Flip a bit in the ciphertext.
    let mut flipped = sealed.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert!(Vault::open(&key, &flipped).is_err());

    // Truncate it.
    assert!(Vault::open(&key, &sealed[..sealed.len() - 4]).is_err());

    // Claim it is a backup file. The magic is covered by the AAD, so this
    // fails even before the kind check would catch it.
    let relabelled = replace_bytes(&sealed, b"MFAVAULT", b"MFABACKP");
    assert!(Vault::open(&key, &relabelled).is_err());
}

#[test]
fn a_contradictory_document_is_rejected() {
    // A tombstone that still carries an account, or a live entry without one,
    // would make `visible()` and `merge()` disagree about what exists.
    let bad = br#"{"format":1,"entries":[{"id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","updated_at":1,"order":0,"deleted":true,"account":{"account":"alice","secret":"JBSWY3DPEHPK3PXP","totp":{"algorithm":"SHA1","digits":6,"period":30}}}]}"#;
    assert!(matches!(
        Vault::from_bytes(bad).unwrap_err(),
        Error::MalformedVault
    ));

    let missing = br#"{"format":1,"entries":[{"id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","updated_at":1,"order":0}]}"#;
    assert!(matches!(
        Vault::from_bytes(missing).unwrap_err(),
        Error::MalformedVault
    ));
}

#[test]
fn a_document_with_unusable_totp_parameters_is_rejected() {
    let bad = br#"{"format":1,"entries":[{"id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","updated_at":1,"order":0,"account":{"account":"alice","secret":"JBSWY3DPEHPK3PXP","totp":{"algorithm":"SHA1","digits":12,"period":30}}}]}"#;
    assert!(Vault::from_bytes(bad).is_err());
}

#[test]
fn a_newer_format_is_refused_rather_than_half_read() {
    let newer = br#"{"format":99,"entries":[]}"#;
    let error = Vault::from_bytes(newer).unwrap_err().to_string();
    assert!(error.contains("newer version"), "unhelpful: {error}");
}
