//! The binding generator.
//!
//! UniFFI's generator has to be built against the same version of UniFFI as
//! the library, so it ships as a binary in this crate rather than being
//! installed separately. `README.md` has the commands.

fn main() {
    uniffi::uniffi_bindgen_main()
}
