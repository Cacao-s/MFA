//! The decrypted vault document.
//!
//! Authenticated before it gets here, so an attacker needs the key — but a
//! member of a sync set has it, and corruption needs no key at all. Every
//! invariant the rest of the code assumes has to be established here.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mfa_core::vault::Vault;
use std::collections::BTreeSet;

fuzz_target!(|data: &[u8]| {
    if let Ok(vault) = Vault::from_bytes(data) {
        let mut ids = BTreeSet::new();
        for entry in &vault.entries {
            assert!(ids.insert(entry.id), "accepted a duplicate entry id");
            assert_eq!(
                entry.deleted,
                entry.account.is_none(),
                "accepted an entry that is both deleted and present"
            );
        }

        // Canonical on the way out, whatever order it arrived in.
        let bytes = vault.to_bytes().expect("a parsed vault serialises");
        let again = Vault::from_bytes(&bytes).expect("our own document");
        assert_eq!(again.to_bytes().unwrap(), bytes);

        // The reads the account list makes every second.
        for entry in vault.visible() {
            if let Some(account) = &entry.account {
                let _ = account.code_at(1_700_000_000);
                let _ = account.totp.remaining_secs_at(1_700_000_000);
            }
        }
    }
});
