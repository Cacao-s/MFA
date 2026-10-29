//! File-based sync through the user's own cloud folder (spec §3).

mod common;

use common::{account, test_kdf};
use mfa_core::vault::Vault;
use mfa_core::{sync, Error};

const T0: i64 = 1_700_000_000_000;
const SYNC_PASSWORD: &str = "a shared sync password";

#[test]
fn a_second_device_joins_with_the_sync_password() {
    let key = sync::new_sync_key();
    let key_file = sync::wrap_key(&key, SYNC_PASSWORD, &test_kdf()).unwrap();

    let on_other_device = sync::unwrap_key(&key_file, SYNC_PASSWORD).unwrap();

    // The unwrapped key really is the same one: it opens a file the first
    // device sealed.
    let mut vault = Vault::new();
    vault.add(account("Example", "alice"), T0);
    let sealed = sync::seal(&vault, &key).unwrap();
    assert_eq!(sync::open(&sealed, &on_other_device).unwrap(), vault);
}

#[test]
fn the_wrong_sync_password_does_not_yield_a_key() {
    let key_file = sync::wrap_key(&sync::new_sync_key(), SYNC_PASSWORD, &test_kdf()).unwrap();

    let error = sync::unwrap_key(&key_file, "wrong").unwrap_err();
    assert!(matches!(error, Error::WrongPassword), "got {error:?}");
}

#[test]
fn an_empty_folder_gets_the_local_vault_uploaded() {
    let key = sync::new_sync_key();
    let mut local = Vault::new();
    local.add(account("Example", "alice"), T0);

    let outcome = sync::reconcile(&local, None, &key).unwrap();
    assert!(outcome.report.is_empty());
    let uploaded = outcome.upload.expect("the first sync has to upload");
    assert_eq!(sync::open(&uploaded, &key).unwrap(), local);
}

#[test]
fn an_unchanged_remote_is_not_rewritten() {
    // Re-uploading an identical vault would churn the user's cloud folder and,
    // on a Git provider, produce an empty commit on every sync.
    let key = sync::new_sync_key();
    let mut local = Vault::new();
    local.add(account("Example", "alice"), T0);
    let remote = sync::seal(&local, &key).unwrap();

    let outcome = sync::reconcile(&local, Some(&remote), &key).unwrap();
    assert!(outcome.report.is_empty());
    assert!(outcome.upload.is_none(), "nothing to upload");
    assert_eq!(outcome.merged, local);
}

#[test]
fn a_remote_change_is_merged_in_and_the_merge_is_published() {
    let key = sync::new_sync_key();

    let mut local = Vault::new();
    local.add(account("Local", "alice"), T0);

    let mut other_device = Vault::new();
    other_device.add(account("Remote", "bob"), T0 + 1_000);
    let remote = sync::seal(&other_device, &key).unwrap();

    let outcome = sync::reconcile(&local, Some(&remote), &key).unwrap();
    assert_eq!(outcome.report.added, 1);
    assert_eq!(outcome.merged.len(), 2);

    // The remote did not have our account, so the merge has to go back up.
    let uploaded = outcome.upload.expect("the remote is behind");
    assert_eq!(sync::open(&uploaded, &key).unwrap(), outcome.merged);
}

#[test]
fn two_devices_converge_after_one_round_each() {
    let key = sync::new_sync_key();

    // Both start from the same vault, then each adds an account offline.
    let mut shared = Vault::new();
    shared.add(account("Shared", "everyone"), T0);
    let mut device_a = shared.clone();
    let mut device_b = shared.clone();
    device_a.add(account("From A", "a"), T0 + 1_000);
    device_b.add(account("From B", "b"), T0 + 2_000);

    // A syncs into an empty folder.
    let mut remote = sync::reconcile(&device_a, None, &key)
        .unwrap()
        .upload
        .unwrap();

    // B syncs, merges A's account and publishes the union.
    let outcome = sync::reconcile(&device_b, Some(&remote), &key).unwrap();
    device_b = outcome.merged;
    remote = outcome.upload.expect("B has something A lacks");
    assert_eq!(device_b.len(), 3);

    // A syncs again and lands on the same document.
    let outcome = sync::reconcile(&device_a, Some(&remote), &key).unwrap();
    device_a = outcome.merged;
    assert!(
        outcome.upload.is_none(),
        "A has nothing left to add, so it must not rewrite the file"
    );
    assert_eq!(
        device_a.to_bytes().unwrap(),
        device_b.to_bytes().unwrap(),
        "both devices must end up with the same vault"
    );
}

#[test]
fn a_delete_on_one_device_does_not_come_back_from_the_other() {
    let key = sync::new_sync_key();

    let mut device_a = Vault::new();
    let id = device_a.add(account("Doomed", "alice"), T0);
    let device_b = device_a.clone();

    // A deletes while B still has the account, and A publishes first.
    device_a.delete(id, T0 + 1_000).unwrap();
    let remote = sync::reconcile(&device_a, None, &key)
        .unwrap()
        .upload
        .unwrap();

    let outcome = sync::reconcile(&device_b, Some(&remote), &key).unwrap();
    assert_eq!(outcome.report.deleted, 1);
    assert!(outcome.merged.get(id).is_none(), "the delete must stick");
    assert!(
        outcome.upload.is_none(),
        "B learnt the delete and has nothing new to publish"
    );
}

#[test]
fn a_sync_file_cannot_be_opened_with_the_wrong_sync_key() {
    let mut local = Vault::new();
    local.add(account("Example", "alice"), T0);
    let sealed = sync::seal(&local, &sync::new_sync_key()).unwrap();

    assert!(sync::open(&sealed, &sync::new_sync_key()).is_err());
    assert!(sync::reconcile(&local, Some(&sealed), &sync::new_sync_key()).is_err());
}

#[test]
fn a_backup_file_is_not_a_sync_file() {
    // They share an envelope format, so the kind has to be checked: importing
    // a backup must go through the password prompt, not the sync key.
    let key = sync::new_sync_key();
    let file = sync::wrap_key(&key, SYNC_PASSWORD, &test_kdf()).unwrap();

    let error = sync::open(&file, &key).unwrap_err();
    assert!(
        matches!(error, Error::WrongFileKind { expected: "sync" }),
        "got {error:?}"
    );
}

#[test]
fn the_same_qr_code_scanned_on_both_devices_ends_up_as_one_row() {
    let key = sync::new_sync_key();

    // Neither device had the account; both scanned the website's QR code, so
    // each minted its own id for it.
    let mut device_a = Vault::new();
    device_a.add(account("Example", "alice"), T0);
    let mut device_b = Vault::new();
    device_b.add(account("Example", "alice"), T0 + 60_000);

    // Which copy survives is decided by the ids, not by who synced first, so
    // nothing here may assume it is A's.
    let mut remote = sync::reconcile(&device_a, None, &key)
        .unwrap()
        .upload
        .unwrap();

    let outcome = sync::reconcile(&device_b, Some(&remote), &key).unwrap();
    device_b = outcome.merged;
    assert_eq!(device_b.len(), 1, "one row after the merge");
    assert_eq!(outcome.report.deduped, 1);
    if let Some(upload) = outcome.upload {
        remote = upload;
    }

    let outcome = sync::reconcile(&device_a, Some(&remote), &key).unwrap();
    device_a = outcome.merged;
    if let Some(upload) = outcome.upload {
        remote = upload;
    }

    assert_eq!(device_a.len(), 1);
    assert_eq!(
        device_a.to_bytes().unwrap(),
        device_b.to_bytes().unwrap(),
        "both devices must hold the same single row"
    );

    // And this is a fixed point: syncing again moves nothing, so the two
    // devices cannot sit rewriting the file at each other forever.
    for device in [&device_a, &device_b] {
        let outcome = sync::reconcile(device, Some(&remote), &key).unwrap();
        assert!(outcome.report.is_empty());
        assert!(outcome.upload.is_none());
        assert_eq!(
            outcome.merged.to_bytes().unwrap(),
            device.to_bytes().unwrap()
        );
    }
}

// --- several targets at once ----------------------------------------------

use mfa_core::sync::RemoteState;
use mfa_core::Uuid;

#[test]
fn one_round_syncs_every_target() {
    let key = sync::new_sync_key();

    let mut local = Vault::new();
    local.add(account("Local", "me"), T0);

    // One target has an account we lack, one has another, one is empty.
    let mut from_drive = Vault::new();
    from_drive.add(account("Drive", "a"), T0 + 1_000);
    let mut from_github = Vault::new();
    from_github.add(account("GitHub", "b"), T0 + 2_000);

    let drive_bytes = sync::seal(&from_drive, &key).unwrap();
    let github_bytes = sync::seal(&from_github, &key).unwrap();
    let (drive, github, server) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

    let outcome = sync::reconcile_all(
        &local,
        &[
            RemoteState {
                target: drive,
                bytes: Some(&drive_bytes),
            },
            RemoteState {
                target: github,
                bytes: Some(&github_bytes),
            },
            RemoteState {
                target: server,
                bytes: None,
            },
        ],
        &key,
    )
    .unwrap();

    assert!(outcome.failures.is_empty());
    assert_eq!(outcome.report.added, 2, "both remote accounts arrive");
    assert_eq!(outcome.merged.len(), 3);

    // All three are behind the merge, so all three get written.
    assert_eq!(outcome.uploads.len(), 3);
    for upload in &outcome.uploads {
        assert_eq!(sync::open(&upload.bytes, &key).unwrap(), outcome.merged);
    }

    // And the round is a fixed point: nothing left to write anywhere.
    let bytes = outcome.uploads[0].bytes.clone();
    let again = sync::reconcile_all(
        &outcome.merged,
        &[
            RemoteState {
                target: drive,
                bytes: Some(&bytes),
            },
            RemoteState {
                target: github,
                bytes: Some(&bytes),
            },
            RemoteState {
                target: server,
                bytes: Some(&bytes),
            },
        ],
        &key,
    )
    .unwrap();
    assert!(again.report.is_empty());
    assert!(again.uploads.is_empty(), "no target needs rewriting");
}

#[test]
fn a_target_that_is_already_current_is_left_alone() {
    // Rewriting it would churn the user's cloud folder, and add an empty
    // commit on a Git target.
    let key = sync::new_sync_key();
    let mut local = Vault::new();
    local.add(account("Example", "alice"), T0);

    let current = sync::seal(&local, &key).unwrap();
    let mut behind_vault = Vault::new();
    behind_vault.settings = local.settings.clone();
    let behind = sync::seal(&behind_vault, &key).unwrap();

    let (up_to_date, stale) = (Uuid::new_v4(), Uuid::new_v4());
    let outcome = sync::reconcile_all(
        &local,
        &[
            RemoteState {
                target: up_to_date,
                bytes: Some(&current),
            },
            RemoteState {
                target: stale,
                bytes: Some(&behind),
            },
        ],
        &key,
    )
    .unwrap();

    assert_eq!(outcome.uploads.len(), 1);
    assert_eq!(outcome.uploads[0].target, stale);
}

#[test]
fn an_unreadable_target_is_reported_and_never_written_over() {
    // Its file may belong to someone else's sync set; overwriting it would
    // destroy whatever accounts are in it.
    let key = sync::new_sync_key();
    let mut local = Vault::new();
    local.add(account("Local", "me"), T0);

    let mut other = Vault::new();
    other.add(account("Drive", "a"), T0 + 1_000);
    let readable = sync::seal(&other, &key).unwrap();
    let foreign = sync::seal(&other, &sync::new_sync_key()).unwrap();

    let (good, bad) = (Uuid::new_v4(), Uuid::new_v4());
    let outcome = sync::reconcile_all(
        &local,
        &[
            RemoteState {
                target: good,
                bytes: Some(&readable),
            },
            RemoteState {
                target: bad,
                bytes: Some(&foreign),
            },
        ],
        &key,
    )
    .unwrap();

    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(outcome.failures[0].0, bad);
    // The readable target still synced: one broken target does not stop the
    // others.
    assert_eq!(outcome.merged.len(), 2);
    assert_eq!(outcome.uploads.len(), 1);
    assert_eq!(outcome.uploads[0].target, good);
}

#[test]
fn a_duplicate_is_collapsed_once_for_the_whole_round() {
    let key = sync::new_sync_key();

    // The same account, scanned separately on this device and on two others.
    let mut local = Vault::new();
    local.add(account("Example", "alice"), T0);
    let mut one = Vault::new();
    one.add(account("Example", "alice"), T0 + 1_000);
    let mut two = Vault::new();
    two.add(account("Example", "alice"), T0 + 2_000);

    let one_bytes = sync::seal(&one, &key).unwrap();
    let two_bytes = sync::seal(&two, &key).unwrap();

    let outcome = sync::reconcile_all(
        &local,
        &[
            RemoteState {
                target: Uuid::new_v4(),
                bytes: Some(&one_bytes),
            },
            RemoteState {
                target: Uuid::new_v4(),
                bytes: Some(&two_bytes),
            },
        ],
        &key,
    )
    .unwrap();

    assert_eq!(outcome.merged.len(), 1, "one row, not three");
    assert_eq!(outcome.report.deduped, 2);
}

#[test]
fn a_cloud_folder_and_a_server_hold_interchangeable_files() {
    // One sync key for the whole set, so moving between targets — or running
    // both — needs no re-keying.
    let key = sync::new_sync_key();
    let mut vault = Vault::new();
    vault.add(account("Example", "alice"), T0);

    let from_folder = sync::seal(&vault, &key).unwrap();
    let onto_server = sync::reconcile(&vault, None, &key).unwrap().upload.unwrap();

    assert_eq!(sync::open(&from_folder, &key).unwrap(), vault);
    assert_eq!(sync::open(&onto_server, &key).unwrap(), vault);
}
