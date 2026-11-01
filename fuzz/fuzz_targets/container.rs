//! The file envelope: magic, version, a length-prefixed JSON header.
//!
//! Reached by importing a backup file and by fetching a sync file from a
//! folder, repository or server someone else can write to.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mfa_core::{backup, container};

fuzz_target!(|data: &[u8]| {
    let _ = container::inspect(data);
    let _ = backup::inspect(data);

    // The password path derives a key from the header's own cost parameters,
    // so this also covers a header asking for an allocation it should not
    // get. Without the bound in `KdfParams::validate` this target runs the
    // machine out of memory rather than finding a crash.
    let _ = backup::import(data, "a password of adequate length");
});
