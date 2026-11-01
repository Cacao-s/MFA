//! `otpauth-migration://` URIs: the Google Authenticator export QR code.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mfa_core::migration;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };

    if let Ok(batch) = migration::parse_migration_uri(text) {
        // A batch that parsed has to describe itself consistently, or the
        // collector's "have I scanned them all" arithmetic is meaningless.
        assert!(batch.expected_batches() >= 1);
        for account in &batch.accounts {
            let _ = account.params.code_at(&account.secret, 1_700_000_000);
        }
    }
});
