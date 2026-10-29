//! Google Authenticator `otpauth-migration://` imports (spec §5).
//!
//! The fixtures below were produced by an independent Python encoder written
//! straight from the published `MigrationPayload` schema
//! (`tools/ga_encode.py`), so they test this crate's decoder rather than
//! restating it.

use mfa_core::migration::{parse_migration_uri, MigrationCollector, SkipReason};
use mfa_core::totp::Algorithm;
use mfa_core::Secret;

/// One QR code: two importable TOTP accounts and one HOTP entry to skip.
const SINGLE: &str = "otpauth-migration://offline?data=Ci4KCkhlbGxvId6tvu8SEWFsaWNlQGV4YW1wbGUuY29tGgdFeGFtcGxlIAEoATACCisKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgNib2IaCEJpZyBDb3JwIAIoAjACCiYKCkhlbGxvId6tvu8SBmxlZ2FjeRoIT2xkIEJhbmsgASgBMAE4BRABGAEgACiHrUs%3D";
/// The same payload with the `data` parameter left un-percent-encoded.
const SINGLE_UNQUOTED: &str = "otpauth-migration://offline?data=Ci4KCkhlbGxvId6tvu8SEWFsaWNlQGV4YW1wbGUuY29tGgdFeGFtcGxlIAEoATACCisKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgNib2IaCEJpZyBDb3JwIAIoAjACCiYKCkhlbGxvId6tvu8SBmxlZ2FjeRoIT2xkIEJhbmsgASgBMAE4BRABGAEgACiHrUs=";
/// Code 1 of 2 and code 2 of 2 of one export (batch id 424242).
const BATCH_0: &str = "otpauth-migration://offline?data=CioKCkhlbGxvId6tvu8SEWZpcnN0QGV4YW1wbGUuY29tGgNPbmUgASgBMAIQARgCIAAosvIZ";
const BATCH_1: &str = "otpauth-migration://offline?data=CjUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEhJzZWNvbmRAZXhhbXBsZS5jb20aA1R3byADKAIwAhABGAIgASiy8hk%3D";
/// A single MD5 entry, which we refuse rather than generate wrong codes for.
const MD5_ONLY: &str = "otpauth-migration://offline?data=CioKCkhlbGxvId6tvu8SD21kNUBleGFtcGxlLmNvbRoFV2VpcmQgBCgBMAIQARgBIAAoCQ%3D%3D";

const HELLO_B32: &str = "JBSWY3DPEHPK3PXP";
const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn parses_a_single_code_export() {
    let batch = parse_migration_uri(SINGLE).unwrap();

    assert_eq!(batch.version, 1);
    assert_eq!(batch.batch_id, 1_234_567);
    assert_eq!(batch.batch_index, 0);
    assert_eq!(batch.expected_batches(), 1);
    assert_eq!(batch.accounts.len(), 2);

    let alice = &batch.accounts[0];
    assert_eq!(alice.issuer.as_deref(), Some("Example"));
    assert_eq!(alice.account, "alice@example.com");
    assert_eq!(alice.secret, Secret::from_base32(HELLO_B32).unwrap());
    assert_eq!(alice.params.algorithm, Algorithm::Sha1);
    assert_eq!(alice.params.digits, 6);
    // The export carries no period; Google Authenticator is always 30s.
    assert_eq!(alice.params.period, 30);

    let bob = &batch.accounts[1];
    assert_eq!(bob.issuer.as_deref(), Some("Big Corp"));
    assert_eq!(bob.account, "bob");
    assert_eq!(bob.secret, Secret::from_base32(RFC_SEED_B32).unwrap());
    assert_eq!(bob.params.algorithm, Algorithm::Sha256);
    assert_eq!(bob.params.digits, 8);
}

#[test]
fn an_hotp_entry_is_reported_rather_than_dropped() {
    let batch = parse_migration_uri(SINGLE).unwrap();

    assert_eq!(batch.skipped.len(), 1);
    assert_eq!(batch.skipped[0].display_name, "Old Bank (legacy)");
    assert_eq!(batch.skipped[0].reason, SkipReason::CounterBased);
    // The user gets a sentence they can act on.
    assert!(batch.skipped[0].reason.to_string().contains("HOTP"));
}

#[test]
fn an_md5_entry_is_reported_rather_than_mis_generated() {
    let batch = parse_migration_uri(MD5_ONLY).unwrap();

    assert!(batch.accounts.is_empty());
    assert_eq!(
        batch.skipped[0].reason,
        SkipReason::UnsupportedAlgorithm("MD5".to_owned())
    );
}

#[test]
fn the_data_parameter_may_arrive_percent_encoded_or_not() {
    let quoted = parse_migration_uri(SINGLE).unwrap();
    let raw = parse_migration_uri(SINGLE_UNQUOTED).unwrap();
    assert_eq!(quoted.accounts, raw.accounts);
}

#[test]
fn a_multi_code_export_only_completes_once_every_code_is_scanned() {
    let mut collector = MigrationCollector::new();

    collector.add_uri(BATCH_0).unwrap();
    assert_eq!(collector.expected(), 2);
    assert_eq!(collector.scanned(), 1);
    assert_eq!(collector.missing_indexes(), vec![1]);
    assert!(!collector.is_complete());

    // Sweeping the camera back over a code already held is not an error.
    collector.add_uri(BATCH_0).unwrap();
    assert_eq!(collector.scanned(), 1);

    collector.add_uri(BATCH_1).unwrap();
    assert!(collector.is_complete());
    assert!(collector.missing_indexes().is_empty());

    let import = collector.finish().unwrap();
    let names: Vec<_> = import
        .accounts
        .iter()
        .map(|account| account.display_name())
        .collect();
    assert_eq!(
        names,
        vec!["One (first@example.com)", "Two (second@example.com)"]
    );
    assert_eq!(import.accounts[1].params.algorithm, Algorithm::Sha512);
    assert_eq!(import.accounts[1].params.digits, 8);
}

#[test]
fn an_incomplete_export_refuses_to_finish() {
    let mut collector = MigrationCollector::new();
    collector.add_uri(BATCH_0).unwrap();

    let error = collector.finish().unwrap_err().to_string();
    assert!(
        error.contains('1') && error.contains('2'),
        "unhelpful: {error}"
    );
}

#[test]
fn codes_from_two_different_exports_are_refused() {
    let mut collector = MigrationCollector::new();
    collector.add_uri(BATCH_0).unwrap();

    // SINGLE has a different batch id: mixing them would silently lose
    // accounts from whichever export the user started with.
    assert!(collector.add_uri(SINGLE).is_err());
}

#[test]
fn malformed_payloads_are_rejected() {
    let cases = [
        "otpauth-migration://offline?data=",
        "otpauth-migration://offline?data=!!!not-base64!!!",
        // Valid Base64, truncated protobuf.
        "otpauth-migration://offline?data=Ci4KCkhlbGxv",
        // Right scheme, no data parameter.
        "otpauth-migration://offline",
        // An otpauth:// URI is not a migration URI.
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP",
    ];

    for case in cases {
        assert!(parse_migration_uri(case).is_err(), "should reject {case}");
    }
}

#[test]
fn imported_accounts_generate_the_same_codes_as_their_uris() {
    // An import is only correct if the account it produces is indistinguishable
    // from the same account added by scanning a plain otpauth:// QR code.
    use mfa_core::OtpauthUri;

    let imported = &parse_migration_uri(SINGLE).unwrap().accounts[1];
    let scanned = OtpauthUri::parse(&format!(
        "otpauth://totp/Big%20Corp:bob?secret={RFC_SEED_B32}&issuer=Big%20Corp&algorithm=SHA256&digits=8&period=30"
    ))
    .unwrap();

    assert_eq!(imported, &scanned);
    // Cross-checked against Python's `hmac` (tools/totp_ref.py): the fixture
    // carries the 20-byte RFC seed, not the 32-byte one Appendix B pairs with
    // SHA256, so this is that seed's own SHA256 value.
    assert_eq!(
        imported.params.code_at(&imported.secret, 59).unwrap(),
        "32247374"
    );
}
