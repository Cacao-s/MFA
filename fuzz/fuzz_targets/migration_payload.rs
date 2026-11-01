//! The hand-rolled protobuf reader, fed straight from the wire.
//!
//! This is the sharpest edge in the crate: a parser we wrote ourselves,
//! reading a length-delimited format, over bytes a stranger chose.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mfa_core::migration;

fuzz_target!(|data: &[u8]| {
    if let Ok(batch) = migration::parse_migration_payload(data) {
        assert!(
            !batch.accounts.is_empty() || !batch.skipped.is_empty(),
            "an empty payload must not parse as a batch"
        );
        for account in &batch.accounts {
            let _ = account.params.code_at(&account.secret, 1_700_000_000);
        }
    }
});
