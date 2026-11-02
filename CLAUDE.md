# Notes for Claude

A TOTP authenticator for Android, iOS, macOS and Windows. Nothing is released
yet.

## Read this first: the spec is not in the repository

`temp/` and `docs/` are gitignored, and that is where `spec.md` and `plan.md`
live. **A cloud session cannot see them.** Code comments cite them ("spec §4",
"spec §5") and those references are real, but you will not be able to open
them. If a question turns on what the spec says, ask rather than guess — and
say which answer you need. Reconstructing intent from the code is fine for
most work and misleading for anything about scope.

What the sections are, from the citations: §1 product definition, §2 the stack
decision, §3 sync and backup, §4 the security model, §5 acceptance criteria.

## Shape of the thing

```
crates/mfa-core        pure Rust: no I/O, no clock, no network
crates/mfa-ffi         UniFFI (Swift, Kotlin) + a C ABI carrying JSON (C#)
crates/mfa-sync-server optional self-hosted server, ciphertext only
apple/                 SwiftUI — one source for macOS and iOS
android/               Compose
windows/               WinUI 3
fuzz/                  cargo-fuzz targets for the parsers
tools/                 independent Python reference implementations
spike/                 step 0, which needs real devices and is not done
```

The stack is decided (spec §2): native UI per platform over the shared Rust
core. It is not Tauri and not Compose Multiplatform; if you find a doc that
implies otherwise, the doc is stale.

## Commands

```sh
make check                 # fmt, clippy -D warnings, all tests. This is the gate.
make test                  # tests alone
make bindings              # generate the Swift and Kotlin bindings
make fuzz                  # list fuzz targets
make fuzz TARGET=otpauth_uri SECONDS=300
make server                # run the sync server (needs MFA_SYNC_TOKEN)
```

`make run` fails on purpose: there is no one app to run. Building a platform
UI needs that platform's SDK and its own script — see `apple/README.md`,
`android/README.md`, `windows/README.md`.

Fuzzing needs a nightly toolchain and `cargo install cargo-fuzz`.

## What can be checked, and where

Find out before claiming anything. One run answers it:

```sh
/opt/homebrew/bin/bash docs/scripts/verify-on-mac.sh </dev/null
```

It runs everything the machine is equipped for and reports the rest as `skip`,
so the summary is also the answer to "what can this machine check?".

On the owner's Mac that is: the Rust gate, the XCFramework, both Apple apps
(compile and link, unsigned), the Swift conformance suite, and the .NET one.
In a Linux container it is the Rust gate and .NET only — no Xcode, and
`dl.google.com` is blocked, so no Android SDK.

Nowhere, on any machine here:

- **The Android app.** It needs the SDK, the NDK and `cargo-ndk`. It has never
  been compiled; the Kotlin conformance suite has never run.
- **The Windows app.** WinUI 3 needs Windows and MSBuild. Only its sync
  provider is checkable, which `conformance/dotnet` does.
- **The step-0 spike.** Real biometric hardware and a real camera on four
  machines.
- **Signing, notarisation and store submission.** The owner's credentials.

A build is not a working app: nothing below the UI — Keychain, Keystore,
DPAPI, Face ID, the camera, the app-switcher thumbnail — has been observed
behaving as the security model assumes. Say which of the two you did.

GitHub's runners can build all four platforms, which is why CI matters here
more than usual. CI is deliberately manual-only — see `.github/workflows/`.

## Invariants worth knowing before changing anything

Each of these has tests whose job is to fail if it is broken. If you find
yourself wanting to relax one, that is a conversation, not a refactor.

- **`mfa-core` touches nothing.** No filesystem, no network, no clock. Time
  arrives as a parameter. That is what makes the whole core testable on Linux
  and identical on four platforms.
- **The merge rule is commutative and idempotent**, and settings merge with
  the same tie-break as entries. Associativity is *not* claimed; nothing needs
  it, because `sync::reconcile_all` absorbs every target and collapses
  duplicates once, and that is the order-independent operation. The laws are
  in `tests/properties.rs`, and the idempotence one has already caught a real
  bug that lived for weeks — if you change `Vault::merge` or `Vault::dedupe`,
  crank the case count up before believing a green run. The comment above
  `proptest_config` in that file says how.
- **Every file header is inside the AEAD's associated data**, and every kind
  of file has magic of its own — vault, backup, sync, sync key. A file of one
  kind must never open as another.
- **A file's declared KDF cost is bounded both ways** (`KdfParams::validate`).
  The value comes from outside and decides an allocation.
- **Parsers never panic.** They are fed by QR codes from sites we do not
  control and files from other people's disks, and the shells call in across
  FFI where an unwind is an abort. New parsing code needs a property test, and
  ideally a fuzz target.
- **Import is all-or-nothing.** `backup::import_into` decrypts and parses
  everything before touching the target vault.
- **Fixtures come from `tools/`, not from the code under test.** A TOTP
  expectation generated by our own TOTP implementation proves nothing. The
  Python scripts there are written from the published specs.
- **No error message or `Debug` output contains secret material.**

## Conventions

- Test names are sentences: `a_stale_revision_is_refused_and_changes_nothing`.
  Test files are organised by acceptance criterion, not by module.
- Comments say why, not what. If a line looks wrong but is deliberate, the
  comment is how the next reader finds that out.
- Commit messages explain the reasoning, not just the change.
- Work on the branch you were told to work on. Do not open a pull request
  unless asked.
