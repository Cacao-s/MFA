//! Properties that have to hold for every input, not just the ones we thought
//! of.
//!
//! The example-based suites next door pin down the cases we reasoned about.
//! This one attacks the two places where that is not enough:
//!
//! - **The parsers.** `otpauth://` URIs, Google Authenticator migration
//!   payloads and container headers all arrive from outside — a QR code on a
//!   website we do not control, a file someone else wrote. None of them may
//!   panic, whatever they contain, because a panic in a shell that calls
//!   across FFI is an abort, not an error message.
//! - **The merge rule.** Spec §3 rests on `Vault::merge` being commutative,
//!   idempotent and associative. Those are laws about *all* pairs of
//!   documents, and `tests/merge.rs` can only show them for the handful it
//!   constructs. Here they are checked against vaults built by applying
//!   random sequences of real edits.

mod common;

use proptest::prelude::*;

use mfa_core::sync::{self, RemoteState};
use mfa_core::vault::{Millis, Settings, Vault};
use mfa_core::{backup, container, migration, Account, Algorithm, OtpauthUri, Secret, TotpParams};
use mfa_core::{Error, Uuid};

// ---------------------------------------------------------------- the pool

/// How many distinct accounts the generated edits draw from.
///
/// Small on purpose: a tiny pool means two devices often add the *same*
/// account independently, which is what exercises the dedupe rule and the
/// `updated_at` tie-break. A large pool would mostly generate disjoint
/// documents, where merging is trivially correct.
const POOL: usize = 4;

/// The nth account of the pool. Deterministic, so two devices adding the same
/// index really do produce byte-identical accounts with different ids.
fn pool_account(n: usize) -> Account {
    let n = n % POOL;
    Account {
        issuer: Some(format!("Issuer {n}")),
        account: format!("user{n}@example.com"),
        // 20 bytes, the SHA1 block size an issuer would normally hand out.
        secret: Secret::from_bytes(vec![n as u8 + 1; 20]).expect("not empty"),
        totp: TotpParams::default(),
        note: None,
    }
}

// ---------------------------------------------------------------- edits

/// One edit a device can make. Deliberately the operations the UI offers, so
/// a generated history is one a user could really have produced.
#[derive(Debug, Clone, Copy)]
enum Op {
    Add(u8),
    Note(u8, u8),
    Delete(u8),
    Reorder(u8),
    ClipboardSecs(u8),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        any::<u8>().prop_map(Op::Add),
        (any::<u8>(), 0u8..4).prop_map(|(which, text)| Op::Note(which, text)),
        any::<u8>().prop_map(Op::Delete),
        any::<u8>().prop_map(Op::Reorder),
        (0u8..90).prop_map(Op::ClipboardSecs),
    ]
}

fn ops(max: usize) -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(op(), 0..max)
}

/// The id of the nth live entry, if there is one.
fn nth_live(vault: &Vault, which: u8) -> Option<Uuid> {
    let live = vault.visible();
    if live.is_empty() {
        return None;
    }
    Some(live[usize::from(which) % live.len()].id)
}

/// Applies `edits` to `vault`, moving `clock` forward one step each time.
fn apply(vault: &mut Vault, edits: &[Op], clock: &mut Millis) {
    for edit in edits {
        *clock += 1_000;
        let now = *clock;
        match *edit {
            Op::Add(which) => {
                vault.add(pool_account(usize::from(which)), now);
            }
            Op::Note(which, text) => {
                if let Some(id) = nth_live(vault, which) {
                    let _ = vault.update(id, now, |account| {
                        account.note = Some(format!("note {text}"));
                    });
                }
            }
            Op::Delete(which) => {
                if let Some(id) = nth_live(vault, which) {
                    let _ = vault.delete(id, now);
                }
            }
            Op::Reorder(seed) => {
                let mut ids: Vec<Uuid> = vault.visible().iter().map(|entry| entry.id).collect();
                if !ids.is_empty() {
                    let by = usize::from(seed) % ids.len();
                    ids.rotate_left(by);
                    vault.reorder(&ids, now);
                }
            }
            Op::ClipboardSecs(secs) => {
                let settings = Settings {
                    clipboard_clear_secs: u32::from(secs) + 1,
                    ..vault.settings.clone()
                };
                vault.set_settings(settings, now);
            }
        }
    }
}

const T0: Millis = 1_700_000_000_000;

/// Builds one vault from a history.
fn built(history: &[Op]) -> Vault {
    let mut vault = Vault::new();
    let mut clock = T0;
    apply(&mut vault, history, &mut clock);
    vault
}

/// Two devices that shared a history and then diverged.
///
/// Both carry on from the same clock, so edits on the two sides frequently
/// land on the same millisecond — which is exactly the tie `Entry::supersedes`
/// has to break the same way on both devices.
fn diverged(shared: &[Op], left: &[Op], right: &[Op]) -> (Vault, Vault) {
    let mut base = Vault::new();
    let mut clock = T0;
    apply(&mut base, shared, &mut clock);

    let mut a = base.clone();
    let mut b = base;
    let mut clock_a = clock;
    let mut clock_b = clock;
    apply(&mut a, left, &mut clock_a);
    apply(&mut b, right, &mut clock_b);
    (a, b)
}

fn merged(mut into: Vault, other: Vault) -> Vault {
    into.merge(other);
    into
}

/// The canonical bytes, as a string, so a failing case prints readably.
fn canonical(vault: &Vault) -> String {
    String::from_utf8(vault.to_bytes().expect("a built vault serialises"))
        .expect("the document is UTF-8")
}

// ---------------------------------------------------------------- generators
// for hostile input

/// A string shaped like an `otpauth://` URI.
///
/// Wholly random bytes bounce off the scheme check and never reach the
/// interesting code, so the generator builds something URI-shaped and then
/// varies every part of it — including the parts that make it invalid.
fn uri_ish() -> impl Strategy<Value = String> {
    let scheme = prop_oneof![
        Just("otpauth"),
        Just("OtpAuth"),
        Just("otpauth-migration"),
        Just("https"),
        Just(""),
    ];
    let kind = prop_oneof![
        Just("totp"),
        Just("TOTP"),
        Just("hotp"),
        Just("steam"),
        Just(""),
    ];
    let pair = prop_oneof![
        "[A-Za-z2-7= -]{0,40}".prop_map(|value| format!("secret={value}")),
        "[0-9]{0,4}".prop_map(|value| format!("digits={value}")),
        "[0-9]{0,6}".prop_map(|value| format!("period={value}")),
        prop_oneof![
            Just("SHA1"),
            Just("sha-256"),
            Just("SHA512"),
            Just("MD5"),
            Just(""),
        ]
        .prop_map(|value| format!("algorithm={value}")),
        "[A-Za-z0-9%+. ]{0,20}".prop_map(|value| format!("issuer={value}")),
        "[a-z]{0,6}".prop_map(|key| format!("{key}=%E0%A4%A")),
        Just("secret".to_owned()),
        Just(String::new()),
    ];

    (
        scheme,
        kind,
        "[A-Za-z0-9:%@. +-]{0,30}",
        prop::collection::vec(pair, 0..6),
    )
        .prop_map(|(scheme, kind, label, pairs)| {
            format!("{scheme}://{kind}/{label}?{}", pairs.join("&"))
        })
}

/// Bytes shaped like one of our container files: real magic, a header that is
/// plausible JSON, and a body that is not.
fn container_ish() -> impl Strategy<Value = Vec<u8>> {
    let magic = prop_oneof![
        Just(&b"MFAVAULT"[..]),
        Just(&b"MFABACKP"[..]),
        Just(&b"MFASYNC1"[..]),
        Just(&b"MFASKEY1"[..]),
        Just(&b"MFANOPE0"[..]),
    ];
    let header = prop_oneof![
        Just(r#"{"cipher":"xchacha20poly1305","nonce":"AAAA"}"#.to_owned()),
        Just(r#"{"cipher":"xchacha20poly1305","nonce":"not base64 at all"}"#.to_owned()),
        Just(r#"{"cipher":"aes-gcm","nonce":"AAAA"}"#.to_owned()),
        Just("{}".to_owned()),
        Just("not json".to_owned()),
        "[ -~]{0,60}".prop_map(|text| text),
    ];

    (
        magic,
        any::<u8>(),
        header,
        any::<u16>(),
        prop::collection::vec(any::<u8>(), 0..80),
    )
        .prop_map(|(magic, version, header, claimed_len, body)| {
            let mut bytes = magic.to_vec();
            bytes.push(version);
            // The claimed header length is sometimes the real one and
            // sometimes a lie, which is the case worth testing.
            let length = if claimed_len % 2 == 0 {
                u16::try_from(header.len()).unwrap_or(u16::MAX)
            } else {
                claimed_len
            };
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend_from_slice(&body);
            bytes
        })
}

// ---------------------------------------------------------------- properties

proptest! {
    // The parser properties are cheap; these settings apply to the whole
    // block, and the few expensive properties below set their own.
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Whatever a QR code contains, parsing it is an error at worst.
    #[test]
    fn parsing_an_otpauth_uri_never_panics(text in uri_ish()) {
        let _ = OtpauthUri::parse(&text);
    }

    #[test]
    fn parsing_arbitrary_text_as_an_otpauth_uri_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = OtpauthUri::parse(&String::from_utf8_lossy(&bytes));
    }

    #[test]
    fn parsing_a_migration_uri_never_panics(text in uri_ish()) {
        let _ = migration::parse_migration_uri(&text);
    }

    /// The hand-rolled protobuf reader, fed straight from the wire.
    #[test]
    fn parsing_a_migration_payload_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = migration::parse_migration_payload(&bytes);
    }

    #[test]
    fn inspecting_a_container_never_panics(bytes in container_ish()) {
        let _ = container::inspect(&bytes);
    }

    #[test]
    fn inspecting_arbitrary_bytes_as_a_container_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        let _ = container::inspect(&bytes);
        let _ = backup::inspect(&bytes);
    }

    #[test]
    fn opening_arbitrary_bytes_as_a_vault_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = Vault::from_bytes(&bytes);
    }

    #[test]
    fn parsing_a_base32_secret_never_panics(text in "[A-Za-z2-7= \t-]{0,80}") {
        let _ = Secret::from_base32(&text);
    }

    #[test]
    fn parsing_an_algorithm_name_never_panics(text in "[A-Za-z0-9 _-]{0,20}") {
        let _ = text.parse::<Algorithm>();
    }

    // --- round trips --------------------------------------------------

    /// A secret survives the Base32 it is stored and transported as.
    #[test]
    fn a_secret_round_trips_through_base32(bytes in prop::collection::vec(any::<u8>(), 1..64)) {
        let secret = Secret::from_bytes(bytes).expect("not empty");
        let text = secret.to_base32();
        prop_assert_eq!(Secret::from_base32(&text).expect("our own Base32"), secret);
    }

    /// Anything we render as a URI, we can read back. This is the path a
    /// "show QR code" screen and a re-export both take.
    /// A label has to say *something*: `otpauth://totp/?secret=…` names no
    /// account and the parser rightly refuses it, so an account with neither
    /// an issuer nor a name is not a case this round trip covers. (It is
    /// storable, which is a small asymmetry between what the vault accepts
    /// and what a "show QR code" screen can render back.)
    #[test]
    fn an_account_round_trips_through_its_uri(
        which in 0usize..POOL,
        issuer in prop::option::of("[A-Za-z0-9 .-]{1,20}"),
        account in "[A-Za-z0-9@.-]{1,20}",
        digits in 6u8..=8,
        period in 1u32..=3600,
        algorithm in prop_oneof![Just(Algorithm::Sha1), Just(Algorithm::Sha256), Just(Algorithm::Sha512)],
    ) {
        let uri = OtpauthUri {
            issuer,
            account,
            secret: pool_account(which).secret,
            params: TotpParams::new(algorithm, digits, period).expect("in range"),
        };

        let rendered = uri.to_uri_string();
        let reparsed = OtpauthUri::parse(&rendered)
            .map_err(|error| TestCaseError::fail(format!("{rendered}: {error}")))?;

        prop_assert_eq!(&reparsed.secret, &uri.secret);
        prop_assert_eq!(&reparsed.params, &uri.params);
        prop_assert_eq!(&reparsed.issuer, &uri.issuer);
        prop_assert_eq!(reparsed.account.trim(), uri.account.trim());
    }

    /// A document survives being written and read, and comes back canonical.
    #[test]
    fn a_vault_round_trips_through_its_bytes(history in ops(10)) {
        let vault = built(&history);
        let bytes = vault.to_bytes().expect("serialises");
        let reparsed = Vault::from_bytes(&bytes).expect("our own document");

        prop_assert_eq!(&reparsed, &vault);
        prop_assert_eq!(reparsed.to_bytes().unwrap(), bytes);
    }

    // --- TOTP ---------------------------------------------------------

    /// A code is always exactly the requested number of digits, zero-padded.
    /// A UI that assumes otherwise lays out a row that sometimes jumps.
    #[test]
    fn a_code_is_always_the_requested_width(
        which in 0usize..POOL,
        digits in 6u8..=8,
        period in 1u32..=3600,
        now in any::<u64>(),
        algorithm in prop_oneof![Just(Algorithm::Sha1), Just(Algorithm::Sha256), Just(Algorithm::Sha512)],
    ) {
        let params = TotpParams::new(algorithm, digits, period).expect("in range");
        let code = params.code_at(&pool_account(which).secret, now).expect("valid params");

        prop_assert_eq!(code.chars().count(), usize::from(digits));
        prop_assert!(code.chars().all(|c| c.is_ascii_digit()), "got {}", code);
    }

    /// The countdown never shows zero and never exceeds the period, so the
    /// ring cannot render past full or empty.
    #[test]
    fn the_countdown_stays_inside_the_period(period in 1u32..=3600, now in any::<u64>()) {
        let params = TotpParams { period, ..TotpParams::default() };
        let remaining = params.remaining_secs_at(now);
        prop_assert!((1..=period).contains(&remaining), "got {}", remaining);
    }

    /// Time only ever moves the counter forward.
    #[test]
    fn the_counter_never_goes_backwards(period in 1u32..=3600, now in any::<u64>(), step in 0u64..100_000) {
        let params = TotpParams { period, ..TotpParams::default() };
        prop_assert!(params.counter_at(now.saturating_add(step)) >= params.counter_at(now));
    }

    /// `TotpParams`'s fields are public and `Deserialize` does not validate,
    /// so a platform shell can hand us anything. The countdown runs every
    /// second: it may not panic, and code generation must refuse rather than
    /// produce a code nobody can use.
    #[test]
    fn unvalidated_parameters_are_refused_but_never_panic(
        digits in any::<u8>(),
        period in any::<u32>(),
        now in any::<u64>(),
    ) {
        let params = TotpParams { algorithm: Algorithm::Sha1, digits, period };

        // These two must survive anything; they are called from the UI loop.
        let _ = params.counter_at(now);
        let remaining = params.remaining_secs_at(now);
        prop_assert!(remaining >= 1);

        let secret = pool_account(0).secret;
        match params.code_at(&secret, now) {
            Ok(code) => {
                prop_assert!((6..=8).contains(&digits), "generated a code for {digits} digits");
                prop_assert!((1..=3600).contains(&period), "generated a code for period {period}");
                prop_assert_eq!(code.chars().count(), usize::from(digits));
            }
            Err(error) => prop_assert!(
                matches!(error, Error::UnsupportedDigits(_) | Error::UnsupportedPeriod(_)),
                "got {error:?}"
            ),
        }
    }
}

proptest! {
    // 48 was too few, and not by a little: the idempotence counterexample
    // below needed a history where two rows become identical *and* the same
    // id exists on both sides with the same timestamp, and it survived the
    // whole project at 48. 512 finds it in seconds. Before trusting a change
    // to the merge rule, crank it:
    //
    //   sed -i '' 's/cases: 512/cases: 20000/' crates/mfa-core/tests/properties.rs
    //
    // 20000 is 26 seconds, which is too slow for `make check` and cheap for
    // the afternoon you spend changing `Vault::merge`.
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// `merge(a, b)` and `merge(b, a)` agree, byte for byte.
    ///
    /// Spec §3 rests on this: each sync target is reconciled against the local
    /// vault independently, so if the order mattered, the order the targets
    /// happened to be read in would change where every device ended up.
    #[test]
    fn merging_is_commutative(shared in ops(6), left in ops(5), right in ops(5)) {
        let (a, b) = diverged(&shared, &left, &right);

        let ab = merged(a.clone(), b.clone());
        let ba = merged(b, a);

        prop_assert_eq!(canonical(&ab), canonical(&ba));
    }

    /// Merging the same copy again changes nothing, and says so.
    ///
    /// Without this, every sync round would find something to write and the
    /// user's cloud folder would never stop churning.
    #[test]
    fn merging_is_idempotent(shared in ops(6), left in ops(5), right in ops(5)) {
        let (a, b) = diverged(&shared, &left, &right);

        let once = merged(a, b.clone());
        let mut twice = once.clone();
        let report = twice.merge(b);

        prop_assert_eq!(canonical(&once), canonical(&twice));
        prop_assert!(report.is_empty(), "a second merge reported {report:?}");
    }

    /// One sync round over several targets lands in the same place whatever
    /// order the targets were read in.
    ///
    /// This is the claim spec §3 actually rests on, and it is not the same as
    /// `merge` being associative — see the note on `Vault::merge`. A round
    /// absorbs every copy and then collapses duplicates once, which is
    /// order-independent; nested merges collapse at each step, and a
    /// duplicate dropped early is no longer there to be compared later.
    #[test]
    fn a_sync_round_is_order_independent(
        shared in ops(5),
        left in ops(4),
        middle in ops(4),
        right in ops(4),
    ) {
        let key = sync::new_sync_key();
        let (first, second) = diverged(&shared, &left, &middle);
        // A third device holding the same accounts under its own ids, which
        // is what two devices that each scanned the same QR code look like.
        let third = merged(built(&shared), built(&right));

        let files: Vec<Vec<u8>> = [&first, &second, &third]
            .iter()
            .map(|vault| sync::seal(vault, &key).expect("seals"))
            .collect();
        let local = built(&shared);

        let forwards: Vec<RemoteState<'_>> = files
            .iter()
            .enumerate()
            .map(|(index, bytes)| RemoteState {
                target: Uuid::from_u128(index as u128 + 1),
                bytes: Some(bytes),
            })
            .collect();
        let backwards: Vec<RemoteState<'_>> = files
            .iter()
            .enumerate()
            .rev()
            .map(|(index, bytes)| RemoteState {
                target: Uuid::from_u128(index as u128 + 1),
                bytes: Some(bytes),
            })
            .collect();

        let one = sync::reconcile_all(&local, &forwards, &key).expect("reconciles");
        let other = sync::reconcile_all(&local, &backwards, &key).expect("reconciles");

        prop_assert_eq!(canonical(&one.merged), canonical(&other.merged));
        prop_assert!(one.failures.is_empty() && other.failures.is_empty());
    }

    /// And the round is a fixed point: syncing again writes nothing.
    #[test]
    fn a_second_sync_round_has_nothing_to_write(shared in ops(5), left in ops(4), right in ops(4)) {
        let key = sync::new_sync_key();
        let (a, b) = diverged(&shared, &left, &right);

        let remote = sync::seal(&b, &key).expect("seals");
        let first = sync::reconcile_all(
            &a,
            &[RemoteState { target: Uuid::from_u128(1), bytes: Some(&remote) }],
            &key,
        ).expect("reconciles");

        // Everyone is now holding what the first round produced.
        let settled = first
            .uploads
            .first()
            .map(|upload| upload.bytes.clone())
            .unwrap_or(remote);
        let second = sync::reconcile_all(
            &first.merged,
            &[RemoteState { target: Uuid::from_u128(1), bytes: Some(&settled) }],
            &key,
        ).expect("reconciles");

        prop_assert!(second.uploads.is_empty(), "a settled round still wanted to write");
        prop_assert_eq!(canonical(&first.merged), canonical(&second.merged));
    }

    /// Absorbing your own document does exactly one thing: collapses the
    /// duplicates it was already carrying.
    ///
    /// Not "changes nothing", which is what this used to claim. A vault built
    /// by local edits alone can hold two identical accounts, because `update`
    /// can make one row match another where `add` refuses to, and the collapse
    /// only ever runs on a merge. So the no-op is the *second* self-merge, and
    /// the first is a dedupe and nothing else — no entry added, updated or
    /// deleted, no settings touched.
    #[test]
    fn merging_a_copy_of_yourself_only_collapses_duplicates(history in ops(10)) {
        let vault = built(&history);

        let mut deduped_alone = vault.clone();
        let collapsed = deduped_alone.dedupe();

        let mut merged_with_self = vault.clone();
        let report = merged_with_self.merge(vault.clone());

        prop_assert_eq!(canonical(&deduped_alone), canonical(&merged_with_self));
        prop_assert_eq!(report.deduped, collapsed.len());
        prop_assert_eq!((report.added, report.updated, report.deleted), (0, 0, 0));
        prop_assert!(!report.settings_updated);
        prop_assert_eq!(report.changed, !collapsed.is_empty(), "reported {:?}", report);

        // And then it is genuinely a no-op.
        let mut again = merged_with_self.clone();
        let second = again.merge(merged_with_self.clone());
        prop_assert_eq!(canonical(&merged_with_self), canonical(&again));
        prop_assert!(second.is_empty(), "the second self-merge reported {second:?}");
    }

    /// A delete is never undone by a device that had not heard about it.
    ///
    /// This is the failure that matters most in practice: an account the user
    /// deliberately removed coming back, which they would not notice until
    /// they tried to log in with a code that no longer works.
    #[test]
    fn a_delete_is_never_resurrected(shared in ops(8), stale in ops(4)) {
        let base = built(&shared);
        let Some(doomed) = nth_live(&base, 0) else {
            return Ok(());
        };

        // The other device never hears about the delete, so everything it
        // does predates it. An edit made *after* a delete is a different
        // story: later modification wins, by design, and that is how a device
        // re-adds an account on purpose.
        let mut behind = base.clone();
        let mut stale_clock = T0 + 100_000;
        apply(&mut behind, &stale, &mut stale_clock);

        let mut deleting = base;
        deleting
            .delete(doomed, T0 + 1_000_000)
            .expect("the entry is live");

        for order in [
            merged(deleting.clone(), behind.clone()),
            merged(behind, deleting),
        ] {
            prop_assert!(
                order.get(doomed).is_none(),
                "the deleted account is back as {:?}",
                order.get(doomed)
            );
            prop_assert!(order.visible().iter().all(|entry| entry.id != doomed));
        }
    }

    /// Two devices that independently scanned the same QR code end up with
    /// one row, and agree on which one. Merging again finds nothing to do, so
    /// the pair is a fixed point rather than a slow ping-pong.
    #[test]
    fn independently_added_duplicates_collapse_to_a_fixed_point(which in 0usize..POOL) {
        let account = pool_account(which);

        let mut a = Vault::new();
        a.add(account.clone(), T0);
        let mut b = Vault::new();
        b.add(account, T0);

        let ab = merged(a.clone(), b.clone());
        let ba = merged(b, a);

        prop_assert_eq!(ab.len(), 1);
        prop_assert_eq!(canonical(&ab), canonical(&ba));

        let mut again = ab.clone();
        let report = again.merge(ba);
        prop_assert!(report.is_empty(), "reported {report:?}");
        prop_assert_eq!(canonical(&ab), canonical(&again));
    }
}

proptest! {
    // Argon2id at the test cost is still tens of milliseconds a case.
    #![proptest_config(ProptestConfig { cases: 8, ..ProptestConfig::default() })]

    /// A backup survives the round trip for any document, and the wrong
    /// password never yields one.
    #[test]
    fn a_backup_round_trips_and_resists_the_wrong_password(
        history in ops(8),
        password in "[ -~]{8,24}",
    ) {
        let vault = built(&history);
        let file = backup::export(&vault, &password, &common::test_kdf())
            .expect("the password is long enough");

        prop_assert_eq!(&backup::import(&file, &password).expect("our own file"), &vault);

        let wrong = format!("{password}x");
        prop_assert!(matches!(
            backup::import(&file, &wrong),
            Err(Error::WrongPassword)
        ));
    }

    /// Flipping any single byte of a backup is detected. The header is inside
    /// the AEAD's associated data, so this covers the cost fields too.
    #[test]
    fn a_tampered_backup_is_always_rejected(at in any::<prop::sample::Index>()) {
        let vault = built(&[Op::Add(0), Op::Add(1)]);
        let password = "correct horse battery staple";
        let file = backup::export(&vault, password, &common::test_kdf()).expect("exports");

        let index = at.index(file.len());
        let mut tampered = file.clone();
        tampered[index] ^= 0x01;

        prop_assert!(
            backup::import(&tampered, password).is_err(),
            "byte {index} of {} could be flipped unnoticed",
            file.len()
        );
    }
}
