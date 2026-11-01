//! Base32 secrets, including the shapes people type by hand: lower case,
//! padding, spaces and dashes used as grouping.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mfa_core::Secret;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };

    if let Ok(secret) = Secret::from_base32(text) {
        // Our own encoding of it has to decode back to the same bytes.
        let encoded = secret.to_base32();
        assert_eq!(
            Secret::from_base32(&encoded).expect("our own Base32"),
            secret
        );
    }
});
