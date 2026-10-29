//! `otpauth://` parsing, including the shapes real issuers emit.

use mfa_core::totp::Algorithm;
use mfa_core::{OtpauthUri, Secret};

const HELLO_B32: &str = "JBSWY3DPEHPK3PXP";

#[test]
fn parses_the_canonical_uri() {
    let uri = OtpauthUri::parse(
        "otpauth://totp/Example:alice@example.com\
         ?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30",
    )
    .unwrap();

    assert_eq!(uri.issuer.as_deref(), Some("Example"));
    assert_eq!(uri.account, "alice@example.com");
    assert_eq!(uri.secret, Secret::from_base32(HELLO_B32).unwrap());
    assert_eq!(uri.params.algorithm, Algorithm::Sha1);
    assert_eq!(uri.params.digits, 6);
    assert_eq!(uri.params.period, 30);
}

#[test]
fn omitted_parameters_fall_back_to_the_defaults() {
    let uri =
        OtpauthUri::parse("otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP").unwrap();

    assert_eq!(uri.issuer, None);
    assert_eq!(uri.account, "alice@example.com");
    assert_eq!(uri.params.algorithm, Algorithm::Sha1);
    assert_eq!(uri.params.digits, 6);
    assert_eq!(uri.params.period, 30);
}

#[test]
fn the_issuer_parameter_wins_over_the_label_prefix() {
    // The label prefix is the legacy channel and is the one issuers truncate.
    let uri = OtpauthUri::parse(
        "otpauth://totp/Short:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Full%20Name%20Ltd",
    )
    .unwrap();

    assert_eq!(uri.issuer.as_deref(), Some("Full Name Ltd"));
    assert_eq!(uri.account, "alice@example.com");
}

#[test]
fn accepts_what_real_issuers_actually_write() {
    // Mixed-case scheme and type, `SHA-256`, lower-case padded secret with
    // the grouping spaces a user types by hand, and a space after the colon.
    let uri = OtpauthUri::parse(
        "OTPAUTH://TOTP/Big%20Corp:%20bob%40example.com\
         ?secret=jbswy3dp%20ehpk3pxp%3D%3D&algorithm=sha-256&digits=8&period=60",
    )
    .unwrap();

    assert_eq!(uri.issuer.as_deref(), Some("Big Corp"));
    assert_eq!(uri.account, "bob@example.com");
    assert_eq!(uri.secret, Secret::from_base32(HELLO_B32).unwrap());
    assert_eq!(uri.params.algorithm, Algorithm::Sha256);
    assert_eq!(uri.params.digits, 8);
    assert_eq!(uri.params.period, 60);
}

#[test]
fn unknown_parameters_are_ignored() {
    let uri = OtpauthUri::parse(
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&image=https://example.com/logo.png&foo=bar",
    )
    .unwrap();
    assert_eq!(uri.account, "alice");
}

#[test]
fn a_uri_survives_a_round_trip() {
    for original in [
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30",
        "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/Odd%20%2F%20Name:a%3Ab?secret=JBSWY3DPEHPK3PXP&issuer=Odd%20%2F%20Name&digits=8&period=60&algorithm=SHA512",
    ] {
        let parsed = OtpauthUri::parse(original).unwrap();
        let reparsed = OtpauthUri::parse(&parsed.to_uri_string()).unwrap();
        assert_eq!(parsed, reparsed, "round trip of {original}");
    }
}

#[test]
fn a_colon_inside_a_name_survives_the_round_trip() {
    // The separator is the *first* colon, so an account containing one has to
    // come back percent-encoded or the issuer would swallow it.
    let parsed =
        OtpauthUri::parse("otpauth://totp/Issuer:user%3Aname?secret=JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(parsed.account, "user:name");

    let reparsed = OtpauthUri::parse(&parsed.to_uri_string()).unwrap();
    assert_eq!(reparsed.issuer.as_deref(), Some("Issuer"));
    assert_eq!(reparsed.account, "user:name");
}

#[test]
fn display_name_reads_as_the_list_shows_it() {
    let with_issuer =
        OtpauthUri::parse("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(with_issuer.display_name(), "Example (alice)");

    let bare = OtpauthUri::parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(bare.display_name(), "alice");
}

#[test]
fn rejects_what_it_cannot_generate_codes_for() {
    let cases = [
        // HOTP is out of scope for v1 and must say so by name.
        "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=1",
        // Not an otpauth URI at all.
        "https://example.com/?secret=JBSWY3DPEHPK3PXP",
        "otpauth:/totp/alice?secret=JBSWY3DPEHPK3PXP",
        // No secret.
        "otpauth://totp/alice",
        "otpauth://totp/alice?issuer=Example",
        // Not Base32.
        "otpauth://totp/alice?secret=not!base32",
        // Empty secret.
        "otpauth://totp/alice?secret=",
        // No label.
        "otpauth://totp/?secret=JBSWY3DPEHPK3PXP",
        // Out-of-range parameters.
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=9",
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=four",
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&period=0",
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
    ];

    for case in cases {
        assert!(OtpauthUri::parse(case).is_err(), "should reject {case}");
    }
}

#[test]
fn error_messages_never_contain_the_secret() {
    let error = OtpauthUri::parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=9")
        .unwrap_err()
        .to_string();
    assert!(!error.contains("JBSWY3DP"), "leaked the secret: {error}");
}

#[test]
fn a_secret_redacts_itself_in_debug_output() {
    let secret = Secret::from_base32(HELLO_B32).unwrap();
    let rendered = format!("{secret:?}");
    assert!(!rendered.contains("JBSWY3DP"), "leaked: {rendered}");
    assert!(rendered.contains("redacted"), "unhelpful: {rendered}");

    // And so does every type that holds one.
    let uri = OtpauthUri::parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP").unwrap();
    assert!(!format!("{uri:?}").contains("JBSWY3DP"));
}
