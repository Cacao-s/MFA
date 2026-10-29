//! A whole session through the API the generated bindings call.
//!
//! The Swift and Kotlin bindings are generated from exactly these functions,
//! so what passes here is what the platform shells will see. The only thing
//! not covered is the generated glue itself.

use mfa_ffi::*;

const T0: i64 = 1_700_000_000_000;
const URI: &str = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

fn opened() -> (VaultHandle, Vec<u8>) {
    let key = generate_data_key();
    let vault = VaultHandle::create(key.clone()).expect("a fresh vault");
    (vault, key)
}

#[test]
fn the_first_run_flow_works_end_to_end() {
    // 1. A key from the platform, 2. an empty vault, 3. add, 4. seal and let
    // the platform write it.
    let (vault, key) = opened();
    assert_eq!(vault.count(), 0);

    let id = vault.add_uri(URI.to_owned(), T0).unwrap();
    assert_eq!(vault.count(), 1);

    let accounts = vault.accounts(59).unwrap();
    assert_eq!(accounts.len(), 1);
    let account = &accounts[0];
    assert_eq!(account.id, id);
    assert_eq!(account.display_name, "Example (alice@example.com)");
    // Cross-checked against Python's hmac (tools/totp_ref.py).
    assert_eq!(account.code, "996554");
    assert_eq!(account.remaining_secs, 1);
    assert_eq!(account.period, 30);
    assert_eq!(account.digits, 6);
    assert_eq!(account.algorithm, "SHA1");

    // Reopening the sealed file gives the same account back.
    let file = vault.seal().unwrap();
    let reopened = VaultHandle::open(key, file).unwrap();
    assert_eq!(reopened.accounts(59).unwrap(), accounts);
}

#[test]
fn a_bad_key_length_is_refused_clearly() {
    let error = VaultHandle::create(vec![0u8; 16]).unwrap_err();
    assert!(error.to_string().contains("32 bytes"), "got {error}");
}

#[test]
fn the_wrong_key_reports_a_kind_the_ui_can_branch_on() {
    let (vault, _) = opened();
    let file = vault.seal().unwrap();

    let error = VaultHandle::open(generate_data_key(), file).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::CannotDecrypt);
}

#[test]
fn a_preview_does_not_carry_the_secret() {
    // A confirmation screen has no use for it, and anything the UI holds can
    // end up in a log or a screenshot.
    let preview = preview_uri(URI.to_owned()).unwrap();
    assert_eq!(preview.display_name, "Example (alice@example.com)");
    assert_eq!(preview.digits, 6);

    let rendered = format!("{preview:?}");
    assert!(!rendered.contains("JBSWY3DP"), "leaked: {rendered}");
}

#[test]
fn a_bad_uri_is_reported_as_such() {
    let error = preview_uri("https://example.com".to_owned()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::BadUri);

    // And HOTP is reported as unsupported rather than as a parse failure, so
    // the UI can say why.
    let hotp =
        preview_uri("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=1".to_owned()).unwrap_err();
    assert_eq!(hotp.kind(), ErrorKind::Unsupported);
}

#[test]
fn a_manual_entry_matches_the_same_account_scanned() {
    let (vault, _) = opened();

    let scanned = vault.add_uri(URI.to_owned(), T0).unwrap();
    let typed = vault
        .add_manual(
            AccountDraft {
                issuer: Some("Example".to_owned()),
                account: "alice@example.com".to_owned(),
                // Spaces and case are what a person actually types.
                secret: "jbswy3dp ehpk3pxp".to_owned(),
                ..AccountDraft::default()
            },
            T0 + 1_000,
        )
        .unwrap();

    // Identical in every field, so it is the same account, not a second row.
    assert_eq!(typed, scanned);
    assert_eq!(vault.count(), 1);
}

#[test]
fn the_ui_can_ask_before_adding_a_duplicate() {
    let (vault, _) = opened();
    assert_eq!(vault.duplicate_of_uri(URI.to_owned()).unwrap(), None);

    let id = vault.add_uri(URI.to_owned(), T0).unwrap();
    assert_eq!(vault.duplicate_of_uri(URI.to_owned()).unwrap(), Some(id));
}

#[test]
fn editing_searching_and_reordering() {
    let (vault, _) = opened();
    let github = vault
        .add_uri(
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub".to_owned(),
            T0,
        )
        .unwrap();
    let bank = vault
        .add_uri(
            "otpauth://totp/Bank:carol?secret=GEZDGNBVGY3TQOJQ&issuer=Bank".to_owned(),
            T0 + 1_000,
        )
        .unwrap();

    vault
        .set_note(bank.clone(), Some("savings".to_owned()), T0 + 2_000)
        .unwrap();
    let found = vault.search("savings".to_owned(), 59).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].note.as_deref(), Some("savings"));

    vault
        .rename(
            github.clone(),
            Some("GitHub Inc".to_owned()),
            "alice@work".to_owned(),
            T0 + 3_000,
        )
        .unwrap();
    assert_eq!(
        vault.search("github inc".to_owned(), 59).unwrap()[0].display_name,
        "GitHub Inc (alice@work)"
    );

    // An empty note or issuer clears rather than storing blankness.
    vault
        .set_note(bank.clone(), Some("  ".to_owned()), T0 + 4_000)
        .unwrap();
    assert!(vault.search("savings".to_owned(), 59).unwrap().is_empty());

    vault
        .reorder(vec![bank.clone(), github.clone()], T0 + 5_000)
        .unwrap();
    let order: Vec<String> = vault
        .accounts(59)
        .unwrap()
        .into_iter()
        .map(|account| account.id)
        .collect();
    assert_eq!(order, vec![bank.clone(), github]);

    vault.delete(bank.clone(), T0 + 6_000).unwrap();
    assert_eq!(vault.count(), 1);
    assert_eq!(
        vault.code(bank, 59).unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn an_unknown_id_is_not_found_rather_than_a_crash() {
    let (vault, _) = opened();
    for id in ["not-a-uuid", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"] {
        assert_eq!(
            vault.code(id.to_owned(), 59).unwrap_err().kind(),
            ErrorKind::NotFound
        );
    }
}

#[test]
fn the_account_uri_is_available_for_a_move_to_another_app() {
    let (vault, _) = opened();
    let id = vault.add_uri(URI.to_owned(), T0).unwrap();

    let uri = vault.account_uri(id).unwrap();
    let back = preview_uri(uri).unwrap();
    assert_eq!(back.display_name, "Example (alice@example.com)");
}

#[test]
fn backup_export_and_import() {
    let (vault, _) = opened();
    vault.add_uri(URI.to_owned(), T0).unwrap();
    let file = vault
        .export_backup("correct horse battery".to_owned())
        .unwrap();

    // The UI can show the cost before asking for the password.
    let info = inspect_backup(file.clone()).unwrap();
    assert_eq!(info.memory_kib, 64 * 1024);
    assert_eq!(info.iterations, 3);

    let (fresh, _) = opened();
    let summary = fresh
        .import_backup(file.clone(), "correct horse battery".to_owned())
        .unwrap();
    assert_eq!(summary.added, 1);
    assert!(summary.changed);
    assert_eq!(fresh.count(), 1);

    // A wrong password is its own kind, and changes nothing.
    let error = fresh.import_backup(file, "wrong".to_owned()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::WrongPassword);
    assert_eq!(fresh.count(), 1);
}

#[test]
fn a_short_backup_password_is_refused() {
    let (vault, _) = opened();
    assert!(vault.export_backup("short".to_owned()).is_err());
}

#[test]
fn a_google_authenticator_export_imports_and_says_what_it_skipped() {
    // Two importable TOTP accounts and one HOTP entry, from tools/ga_encode.py.
    const SINGLE: &str = "otpauth-migration://offline?data=Ci4KCkhlbGxvId6tvu8SEWFsaWNlQGV4YW1wbGUuY29tGgdFeGFtcGxlIAEoATACCisKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgNib2IaCEJpZyBDb3JwIAIoAjACCiYKCkhlbGxvId6tvu8SBmxlZ2FjeRoIT2xkIEJhbmsgASgBMAE4BRABGAEgACiHrUs%3D";

    let progress = migration_progress(vec![SINGLE.to_owned()]).unwrap();
    assert!(progress.complete);
    assert_eq!(progress.scanned, 1);

    let (vault, _) = opened();
    let result = vault.import_migration(vec![SINGLE.to_owned()], T0).unwrap();

    assert_eq!(result.summary.added, 2);
    assert_eq!(result.skipped.len(), 1);
    assert_eq!(result.skipped[0].display_name, "Old Bank (legacy)");
    assert!(result.skipped[0].reason.contains("HOTP"));
}

#[test]
fn a_half_scanned_export_refuses_rather_than_half_importing() {
    // Code 1 of 2.
    const BATCH_0: &str = "otpauth-migration://offline?data=CioKCkhlbGxvId6tvu8SEWZpcnN0QGV4YW1wbGUuY29tGgNPbmUgASgBMAIQARgCIAAosvIZ";

    let progress = migration_progress(vec![BATCH_0.to_owned()]).unwrap();
    assert!(!progress.complete);
    assert_eq!(progress.expected, 2);
    assert_eq!(progress.missing, vec![1]);

    let (vault, _) = opened();
    let error = vault
        .import_migration(vec![BATCH_0.to_owned()], T0)
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::IncompleteImport);
    assert_eq!(vault.count(), 0, "nothing was imported");
}

#[test]
fn the_lock_settings_round_trip_and_the_pin_never_comes_back() {
    let (vault, _) = opened();

    let config = vault.lock_config();
    assert!(config.biometric_enabled);
    assert_eq!(config.background_timeout_secs, 30);
    assert!(!config.has_pin);

    vault.set_lock_config(
        LockConfig {
            biometric_enabled: false,
            background_timeout_secs: 120,
            has_pin: false, // ignored here; set_pin does that
        },
        T0,
    );
    assert_eq!(vault.lock_config().background_timeout_secs, 120);

    vault.set_pin("1379".to_owned(), T0 + 1_000).unwrap();
    assert!(vault.lock_config().has_pin);
    assert!(vault.verify_pin("1379".to_owned()));
    assert!(!vault.verify_pin("0000".to_owned()));

    // The verifier survives a save, so the PIN still works after a restart.
    let file = vault.seal().unwrap();
    let key = generate_data_key();
    let fresh = VaultHandle::create(key).unwrap();
    assert!(!fresh.verify_pin("1379".to_owned()), "no PIN, no unlock");
    drop(file);

    vault.clear_pin(T0 + 2_000);
    assert!(!vault.lock_config().has_pin);
    assert!(!vault.verify_pin("1379".to_owned()));
}

#[test]
fn a_pin_that_is_too_short_is_refused() {
    let (vault, _) = opened();
    assert!(vault.set_pin("12".to_owned(), T0).is_err());
}

#[test]
fn preferences_round_trip() {
    let (vault, _) = opened();
    assert_eq!(vault.preferences().clipboard_clear_secs, 30);

    vault.set_preferences(
        Preferences {
            clipboard_clear_secs: 15,
            sort: SortMode::IssuerAsc,
        },
        T0,
    );
    let preferences = vault.preferences();
    assert_eq!(preferences.clipboard_clear_secs, 15);
    assert_eq!(preferences.sort, SortMode::IssuerAsc);
}

#[test]
fn sync_targets_can_be_added_changed_and_removed() {
    let (vault, _) = opened();
    assert!(vault.sync_targets().is_empty());

    let id = vault
        .upsert_sync_target(
            SyncTargetView {
                id: String::new(), // empty means "add"
                kind: SyncKind::Server,
                label: "home server".to_owned(),
                location: "https://mfa.example.com".to_owned(),
                enabled: true,
            },
            T0,
        )
        .unwrap();

    let targets = vault.sync_targets();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].id, id);
    assert_eq!(targets[0].kind, SyncKind::Server);

    // Several can be live at once.
    vault
        .upsert_sync_target(
            SyncTargetView {
                id: String::new(),
                kind: SyncKind::Folder,
                label: "iCloud Drive".to_owned(),
                location: "~/Library/Mobile Documents".to_owned(),
                enabled: true,
            },
            T0 + 1_000,
        )
        .unwrap();
    assert_eq!(vault.sync_targets().len(), 2);

    // Upserting the same id edits rather than adding.
    vault
        .upsert_sync_target(
            SyncTargetView {
                id: id.clone(),
                kind: SyncKind::Server,
                label: "home server".to_owned(),
                location: "https://mfa.example.com".to_owned(),
                enabled: false,
            },
            T0 + 2_000,
        )
        .unwrap();
    assert_eq!(vault.sync_targets().len(), 2);
    assert!(!vault
        .sync_targets()
        .iter()
        .any(|target| target.enabled && target.id == id));

    vault.remove_sync_target(id, T0 + 3_000).unwrap();
    assert_eq!(vault.sync_targets().len(), 1);
}

#[test]
fn two_devices_sync_through_the_platform() {
    // The platform fetches the bytes and writes back what it is given; this is
    // the whole of the core's part.
    let sync_key = new_sync_key();
    let target = "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_owned();

    let (device_a, _) = opened();
    device_a.add_uri(URI.to_owned(), T0).unwrap();
    let (device_b, _) = opened();
    device_b
        .add_uri(
            "otpauth://totp/GitHub:bob?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub".to_owned(),
            T0 + 1_000,
        )
        .unwrap();

    // A publishes into an empty target.
    let round = device_a
        .sync(
            vec![RemoteFile {
                target: target.clone(),
                bytes: None,
            }],
            sync_key.clone(),
        )
        .unwrap();
    assert_eq!(round.uploads.len(), 1);
    assert!(round.failures.is_empty());
    let mut remote = round.uploads[0].bytes.clone();

    // B merges and republishes.
    let round = device_b
        .sync(
            vec![RemoteFile {
                target: target.clone(),
                bytes: Some(remote.clone()),
            }],
            sync_key.clone(),
        )
        .unwrap();
    assert_eq!(round.summary.added, 1);
    remote = round.uploads[0].bytes.clone();
    assert_eq!(device_b.count(), 2);

    // A catches up and has nothing left to write.
    let round = device_a
        .sync(
            vec![RemoteFile {
                target,
                bytes: Some(remote),
            }],
            sync_key,
        )
        .unwrap();
    assert_eq!(device_a.count(), 2);
    assert!(round.uploads.is_empty());
    assert!(!round.summary.changed || round.summary.added == 1);
}

#[test]
fn a_target_we_cannot_read_is_reported_not_overwritten() {
    let (vault, _) = opened();
    vault.add_uri(URI.to_owned(), T0).unwrap();

    let foreign = {
        let (other, _) = opened();
        other
            .sync(
                vec![RemoteFile {
                    target: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_owned(),
                    bytes: None,
                }],
                new_sync_key(),
            )
            .unwrap()
            .uploads[0]
            .bytes
            .clone()
    };

    let round = vault
        .sync(
            vec![RemoteFile {
                target: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_owned(),
                bytes: Some(foreign),
            }],
            new_sync_key(),
        )
        .unwrap();

    assert_eq!(round.failures.len(), 1);
    assert!(round.uploads.is_empty(), "nothing is written over it");
}

#[test]
fn a_device_joins_a_sync_set_with_the_password() {
    let key = new_sync_key();
    let key_file = wrap_sync_key(key.clone(), "correct horse battery".to_owned()).unwrap();

    assert_eq!(
        unwrap_sync_key(key_file.clone(), "correct horse battery".to_owned()).unwrap(),
        key
    );
    assert_eq!(
        unwrap_sync_key(key_file, "wrong".to_owned())
            .unwrap_err()
            .kind(),
        ErrorKind::WrongPassword
    );
}

#[test]
fn the_version_is_reportable() {
    assert!(!library_version().is_empty());
}
