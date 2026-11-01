//! `otpauth://` URIs, which arrive from a QR code on a site we do not control
//! or from whatever the user pasted.
//!
//! A panic here is not an error path: the platform shells call in across FFI,
//! where an unwind becomes an abort.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mfa_core::OtpauthUri;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };

    if let Ok(uri) = OtpauthUri::parse(text) {
        // What we accept, we must be able to render and read back.
        let rendered = uri.to_uri_string();
        let reparsed = OtpauthUri::parse(&rendered)
            .expect("a URI we generated ourselves has to parse again");
        assert_eq!(reparsed.secret, uri.secret, "{rendered}");
        assert_eq!(reparsed.params, uri.params, "{rendered}");

        // And generating a code must not panic for any parameters we admit.
        let _ = uri.params.code_at(&uri.secret, 1_700_000_000);
    }
});
