//! Image bytes handed to the desktop "add from a screen grab" path.
//!
//! The decoders are third-party, which is the reason to fuzz this rather than
//! assume it: a malformed PNG reaches them before it reaches us.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mfa_core::qr;

fuzz_target!(|data: &[u8]| {
    let _ = qr::decode_image(data);
    let _ = qr::decode_otp_uris(data);
});
