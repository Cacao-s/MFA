//! The merge rule (spec §3): two copies of the vault have to converge, in
//! either direction, however many times they are merged.

mod common;

use common::account;
use mfa_core::vault::{SortMode, Vault};
use mfa_core::Uuid;

const T0: i64 = 1_700_000_000_000;

/// Two vaults holding the same entry id, so they describe the same account.
fn divergent_pair() -> (Vault, Vault, Uuid) {
    let mut left = Vault::new();
    let id = left.add(account("Example", "alice"), T0);
    let right = left.clone();
    (left, right, id)
}

#[test]
fn an_account_only_one_side_has_is_added() {
    let (mut left, mut right, _) = divergent_pair();
    right.add(account("GitHub", "bob"), T0 + 1_000);

    let report = left.merge(right);
    assert_eq!(report.added, 1);
    assert_eq!(report.unchanged, 1);
    assert_eq!(left.len(), 2);
}

#[test]
fn the_later_edit_wins() {
    let (mut left, mut right, id) = divergent_pair();

    left.update(id, T0 + 1_000, |account| {
        account.note = Some("older".to_owned())
    })
    .unwrap();
    right
        .update(id, T0 + 2_000, |account| {
            account.note = Some("newer".to_owned())
        })
        .unwrap();

    let report = left.merge(right);
    assert_eq!(report.updated, 1);
    assert_eq!(
        left.get(id)
            .unwrap()
            .account
            .as_ref()
            .unwrap()
            .note
            .as_deref(),
        Some("newer")
    );
}

#[test]
fn an_older_edit_does_not_beat_a_newer_delete() {
    let (mut left, mut right, id) = divergent_pair();

    left.update(id, T0 + 1_000, |account| {
        account.note = Some("still editing".to_owned())
    })
    .unwrap();
    right.delete(id, T0 + 2_000).unwrap();

    left.merge(right);
    assert!(left.get(id).is_none(), "the delete should win");
}

#[test]
fn a_newer_edit_does_beat_an_older_delete() {
    // Deliberately asymmetric with the test above: recency decides, not the
    // kind of change. Re-adding an account a user deleted is as wrong as
    // dropping an edit they made.
    let (mut left, mut right, id) = divergent_pair();

    left.delete(id, T0 + 1_000).unwrap();
    right
        .update(id, T0 + 2_000, |account| {
            account.note = Some("still wanted".to_owned())
        })
        .unwrap();

    left.merge(right);
    assert!(left.get(id).is_some(), "the edit should win");
}

#[test]
fn a_delete_wins_an_exact_tie() {
    // Clocks on two devices can agree to the millisecond. Resurrecting a
    // deleted account is the worse failure, so the tombstone takes the tie.
    let (mut left, mut right, id) = divergent_pair();

    left.update(id, T0 + 1_000, |account| {
        account.note = Some("edited".to_owned())
    })
    .unwrap();
    right.delete(id, T0 + 1_000).unwrap();

    let mut reversed = right.clone();
    reversed.merge(left.clone());
    left.merge(right);

    assert!(left.get(id).is_none());
    assert!(reversed.get(id).is_none());
}

#[test]
fn merging_is_commutative() {
    let (mut left, mut right, id) = divergent_pair();
    left.update(id, T0 + 1_000, |a| a.note = Some("left".to_owned()))
        .unwrap();
    left.add(account("Only Left", "x"), T0 + 1_500);
    right.add(account("Only Right", "y"), T0 + 2_000);
    let deleted = right.add(account("Doomed", "z"), T0 + 500);
    right.delete(deleted, T0 + 2_500).unwrap();

    let mut forward = left.clone();
    forward.merge(right.clone());
    let mut backward = right;
    backward.merge(left);

    assert_eq!(
        forward.to_bytes().unwrap(),
        backward.to_bytes().unwrap(),
        "merge(a, b) and merge(b, a) must agree"
    );
}

#[test]
fn merging_is_idempotent() {
    let (mut left, mut right, id) = divergent_pair();
    right
        .update(id, T0 + 1_000, |a| a.note = Some("newer".to_owned()))
        .unwrap();
    right.add(account("GitHub", "bob"), T0 + 1_000);

    left.merge(right.clone());
    let once = left.to_bytes().unwrap();

    let report = left.merge(right);
    assert!(report.is_empty(), "a second merge should change nothing");
    assert_eq!(left.to_bytes().unwrap(), once);
}

#[test]
fn a_tombstone_for_an_unknown_account_is_kept() {
    // Device C deleted an account this device never saw. Dropping the
    // tombstone here would let device B re-add it on the next round.
    let mut local = Vault::new();
    local.add(account("Example", "alice"), T0);

    let mut remote = Vault::new();
    let doomed = remote.add(account("Elsewhere", "bob"), T0);
    remote.delete(doomed, T0 + 1_000).unwrap();

    local.merge(remote);
    assert_eq!(local.len(), 1);
    assert!(
        local
            .entries
            .iter()
            .any(|entry| entry.id == doomed && entry.deleted),
        "the tombstone should be carried over"
    );
}

#[test]
fn settings_merge_as_one_unit_by_their_own_timestamp() {
    let (mut left, mut right, _) = divergent_pair();

    let mut local = left.settings.clone();
    local.clipboard_clear_secs = 10;
    left.set_settings(local, T0 + 1_000);

    let mut incoming = right.settings.clone();
    incoming.clipboard_clear_secs = 60;
    incoming.sort = SortMode::IssuerAsc;
    right.set_settings(incoming, T0 + 2_000);

    let report = left.merge(right);
    assert!(report.settings_updated);
    assert_eq!(left.settings.clipboard_clear_secs, 60);
    assert_eq!(left.settings.sort, SortMode::IssuerAsc);
}

#[test]
fn older_settings_are_ignored() {
    let (mut left, mut right, _) = divergent_pair();

    let mut local = left.settings.clone();
    local.clipboard_clear_secs = 10;
    left.set_settings(local, T0 + 2_000);

    let mut incoming = right.settings.clone();
    incoming.clipboard_clear_secs = 60;
    right.set_settings(incoming, T0 + 1_000);

    let report = left.merge(right);
    assert!(!report.settings_updated);
    assert_eq!(left.settings.clipboard_clear_secs, 10);
}

#[test]
fn tombstones_are_pruned_only_once_they_are_old_enough() {
    let mut vault = Vault::new();
    let old = vault.add(account("Old", "a"), T0);
    let recent = vault.add(account("Recent", "b"), T0);
    vault.delete(old, T0).unwrap();
    vault.delete(recent, T0 + 100 * 86_400_000).unwrap();

    let retention = mfa_core::vault::TOMBSTONE_RETENTION_MS;
    let now = T0 + 190 * 86_400_000;

    assert_eq!(vault.prune_tombstones(now, retention), 1);
    assert!(!vault.entries.iter().any(|entry| entry.id == old));
    assert!(vault.entries.iter().any(|entry| entry.id == recent));
}

#[test]
fn three_devices_converge() {
    // The real shape of file sync: everyone merges everyone, in whatever
    // order their syncs happen to run.
    let mut a = Vault::new();
    let shared = a.add(account("Shared", "everyone"), T0);
    let mut b = a.clone();
    let mut c = a.clone();

    a.add(account("From A", "a"), T0 + 1_000);
    b.update(shared, T0 + 2_000, |account| {
        account.note = Some("edited on B".to_owned())
    })
    .unwrap();
    let doomed = c.add(account("From C", "c"), T0 + 500);
    c.delete(doomed, T0 + 3_000).unwrap();

    // A different merge order on each device.
    let mut first = a.clone();
    first.merge(b.clone());
    first.merge(c.clone());

    let mut second = b.clone();
    second.merge(c.clone());
    second.merge(a.clone());

    let mut third = c;
    third.merge(a);
    third.merge(b);

    let bytes = first.to_bytes().unwrap();
    assert_eq!(second.to_bytes().unwrap(), bytes);
    assert_eq!(third.to_bytes().unwrap(), bytes);
    assert_eq!(first.len(), 2);
    assert_eq!(
        first
            .get(shared)
            .unwrap()
            .account
            .as_ref()
            .unwrap()
            .note
            .as_deref(),
        Some("edited on B")
    );
}

// --- duplicates -----------------------------------------------------------

/// Two devices that each scanned the same QR code: identical accounts, their
/// own UUIDs.
fn scanned_twice() -> (Vault, Vault) {
    let mut left = Vault::new();
    left.add(account("Example", "alice"), T0);
    let mut right = Vault::new();
    right.add(account("Example", "alice"), T0 + 5_000);
    (left, right)
}

#[test]
fn the_same_account_scanned_on_two_devices_collapses_to_one() {
    let (mut left, right) = scanned_twice();
    let kept = left.entries[0].id.min(right.entries[0].id);

    let report = left.merge(right);

    assert_eq!(left.len(), 1, "one row, not two");
    assert_eq!(report.deduped, 1);
    assert_eq!(left.entries[0].id, kept);
}

#[test]
fn both_devices_keep_the_same_one() {
    // The choice has to be the same on every device, or they would each keep
    // their own copy and never converge.
    let (left, right) = scanned_twice();

    let mut forward = left.clone();
    forward.merge(right.clone());
    let mut backward = right;
    backward.merge(left);

    assert_eq!(forward.to_bytes().unwrap(), backward.to_bytes().unwrap());
}

#[test]
fn a_duplicate_arriving_from_elsewhere_is_not_reported_as_a_change() {
    // The local document ends up exactly as it was, so a sync must not decide
    // it has something new to publish.
    let (left, right) = scanned_twice();
    // Make the local copy the one that survives.
    let (mut left, right) = if left.entries[0].id < right.entries[0].id {
        (left, right)
    } else {
        (right, left)
    };
    let before = left.to_bytes().unwrap();

    let report = left.merge(right);

    assert_eq!(report.deduped, 1);
    assert_eq!(report.added, 0);
    assert!(report.is_empty(), "the document did not change");
    assert_eq!(left.to_bytes().unwrap(), before);
}

#[test]
fn accounts_that_differ_at_all_are_left_alone() {
    // "Identical" means every field. Anything less and we would be deleting
    // an account the user might have meant to keep.
    let differences: Vec<fn(&mut mfa_core::vault::Account)> = vec![
        |account| account.note = Some("work".to_owned()),
        |account| account.totp.period = 60,
        |account| account.totp.digits = 8,
        |account| account.account = "alice2".to_owned(),
        |account| account.issuer = Some("Example Inc".to_owned()),
    ];

    for difference in differences {
        let (mut left, mut right) = scanned_twice();
        let id = right.entries[0].id;
        right.update(id, T0 + 6_000, difference).unwrap();

        let report = left.merge(right);
        assert_eq!(report.deduped, 0);
        assert_eq!(left.len(), 2, "a difference means two accounts");
    }
}

#[test]
fn a_deleted_account_is_never_deduped_against_a_live_one() {
    let (mut left, mut right) = scanned_twice();
    let id = right.entries[0].id;
    right.delete(id, T0 + 6_000).unwrap();

    left.merge(right);

    // The tombstone has to stay — it is how the other device's delete travels
    // — and it must not swallow the live account on this one.
    assert_eq!(left.len(), 1);
    assert_eq!(left.entries.len(), 2);
    assert!(left
        .entries
        .iter()
        .any(|entry| entry.id == id && entry.deleted));
}

#[test]
fn three_devices_converge_on_one_copy_of_a_duplicate() {
    let mut a = Vault::new();
    a.add(account("Example", "alice"), T0);
    let mut b = Vault::new();
    b.add(account("Example", "alice"), T0 + 1_000);
    let mut c = Vault::new();
    c.add(account("Example", "alice"), T0 + 2_000);

    let mut first = a.clone();
    first.merge(b.clone());
    first.merge(c.clone());

    let mut second = b.clone();
    second.merge(c.clone());
    second.merge(a.clone());

    let mut third = c;
    third.merge(a);
    third.merge(b);

    assert_eq!(first.len(), 1);
    let bytes = first.to_bytes().unwrap();
    assert_eq!(second.to_bytes().unwrap(), bytes);
    assert_eq!(third.to_bytes().unwrap(), bytes);
}

#[test]
fn deduping_twice_changes_nothing() {
    let (mut left, right) = scanned_twice();
    left.merge(right);
    let once = left.to_bytes().unwrap();

    assert_eq!(left.dedupe(), 0);
    assert_eq!(left.to_bytes().unwrap(), once);
}
