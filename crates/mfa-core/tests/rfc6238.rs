//! The RFC 6238 Appendix B test vectors, verbatim.
//!
//! These are the acceptance criterion for code generation (spec §5): if this
//! file passes, every code the app shows is right.

use mfa_core::{Algorithm, Secret, TotpParams};

/// RFC 6238 Appendix B seeds: ASCII digits repeated to the hash's key length.
fn seed(algorithm: Algorithm) -> Secret {
    let bytes = match algorithm {
        Algorithm::Sha1 => b"12345678901234567890".to_vec(),
        Algorithm::Sha256 => b"12345678901234567890123456789012".to_vec(),
        Algorithm::Sha512 => {
            b"1234567890123456789012345678901234567890123456789012345678901234".to_vec()
        }
    };
    Secret::from_bytes(bytes).expect("the RFC seeds are non-empty")
}

/// `(T, SHA1, SHA256, SHA512)` at 8 digits and a 30-second step.
const VECTORS: &[(u64, &str, &str, &str)] = &[
    (59, "94287082", "46119246", "90693936"),
    (1_111_111_109, "07081804", "68084774", "25091201"),
    (1_111_111_111, "14050471", "67062674", "99943326"),
    (1_234_567_890, "89005924", "91819424", "93441116"),
    (2_000_000_000, "69279037", "90698825", "38618901"),
    (20_000_000_000, "65353130", "77737706", "47863826"),
];

#[test]
fn appendix_b_vectors() {
    for &(time, sha1, sha256, sha512) in VECTORS {
        for (algorithm, expected) in [
            (Algorithm::Sha1, sha1),
            (Algorithm::Sha256, sha256),
            (Algorithm::Sha512, sha512),
        ] {
            let params = TotpParams::new(algorithm, 8, 30).expect("valid parameters");
            let code = params
                .code_at(&seed(algorithm), time)
                .expect("valid parameters generate a code");
            assert_eq!(code, expected, "{algorithm} at T={time}");
        }
    }
}

#[test]
fn six_digit_codes_are_the_last_six_of_the_eight_digit_code() {
    // Truncation is the same computation at a smaller modulus, so this holds
    // for every vector and catches an off-by-one in the modulus.
    for &(time, sha1, _, _) in VECTORS {
        let params = TotpParams::new(Algorithm::Sha1, 6, 30).expect("valid parameters");
        let code = params.code_at(&seed(Algorithm::Sha1), time).unwrap();
        assert_eq!(code, sha1[2..], "SHA1 at T={time}");
    }
}

#[test]
fn codes_are_zero_padded_to_the_requested_width() {
    let params = TotpParams::new(Algorithm::Sha1, 8, 30).unwrap();
    let code = params
        .code_at(&seed(Algorithm::Sha1), 1_111_111_109)
        .unwrap();
    assert_eq!(code, "07081804");
    assert_eq!(code.len(), 8);
}

#[test]
fn counter_and_countdown_track_the_step_boundary() {
    let params = TotpParams::new(Algorithm::Sha1, 6, 30).unwrap();

    assert_eq!(params.counter_at(0), 0);
    assert_eq!(params.counter_at(29), 0);
    assert_eq!(params.counter_at(30), 1);
    assert_eq!(params.counter_at(59), 1);

    // A full period remains exactly on a boundary, and one second at the end.
    assert_eq!(params.remaining_secs_at(30), 30);
    assert_eq!(params.remaining_secs_at(31), 29);
    assert_eq!(params.remaining_secs_at(59), 1);

    let sixty = TotpParams::new(Algorithm::Sha1, 6, 60).unwrap();
    assert_eq!(sixty.counter_at(59), 0);
    assert_eq!(sixty.counter_at(60), 1);
    assert_eq!(sixty.remaining_secs_at(90), 30);
}

#[test]
fn the_previous_step_differs_from_the_current_one() {
    let params = TotpParams::new(Algorithm::Sha1, 6, 30).unwrap();
    let secret = seed(Algorithm::Sha1);

    let current = params.code_at(&secret, 1_111_111_111).unwrap();
    let previous = params.code_at_offset(&secret, 1_111_111_111, -1).unwrap();
    let next = params.code_at_offset(&secret, 1_111_111_111, 1).unwrap();

    assert_ne!(current, previous);
    assert_ne!(current, next);
    // T=1111111109 is one step before T=1111111111.
    assert_eq!(previous, params.code_at(&secret, 1_111_111_109).unwrap());
}

#[test]
fn invalid_parameters_are_rejected() {
    assert!(TotpParams::new(Algorithm::Sha1, 5, 30).is_err());
    assert!(TotpParams::new(Algorithm::Sha1, 9, 30).is_err());
    assert!(TotpParams::new(Algorithm::Sha1, 6, 0).is_err());
    assert!(TotpParams::new(Algorithm::Sha1, 6, 3601).is_err());
}
