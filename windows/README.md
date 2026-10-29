# MFA for Windows

WinUI 3 over the Rust core, reached through the JSON command bus on the C ABI.

> **None of this has been compiled.** It was written on a machine with no
> Windows SDK. Expect to fix things on the first build — a namespace, a WinUI
> API that moved, a packaging setting. The shape and the decisions are the
> useful part.

## Building

```powershell
# 1. The core, as a DLL next to the executable.
rustup target add x86_64-pc-windows-msvc
cargo build -p mfa-ffi --release --features qr-image --target x86_64-pc-windows-msvc

# 2. The app.
cd windows
dotnet build MFA.sln -c Debug -p:Platform=x64
```

`MFA.csproj` copies `target\<triple>\release\mfa_ffi.dll` next to the output,
because `LibraryImport` looks the library up by name at the first call. Build
the core with `--features qr-image` or "read a QR code from a picture" fails
with an unknown-method error.

The `Assets\` logos are not in the repository; see `MFA\Assets\README.md`. The
unpackaged build does not need them.

## Why a JSON bus and not generated bindings

UniFFI, which generates the Swift and Kotlin bindings, has no first-party C#
generator. A third-party one exists, but it has to track UniFFI's internal ABI,
and a mismatch there surfaces as memory corruption rather than a compile error.

So Windows goes through two exported functions carrying JSON
(`crates/mfa-ffi/src/capi.rs`), wrapped once in `Core/VaultHandle.cs` to give
the rest of the app a typed face. The whole bridge is reviewable in one
sitting, and `Core/MfaCore.cs` is the only file that touches a pointer.

Byte arrays travel as Base64, which is what `JsonSerializer` does with
`byte[]` by default, so there is no converter to get wrong. Both directions are
pinned by tests on the Rust side.

## Layout

| Path | What |
|---|---|
| `Core/` | The bridge: P/Invoke, the typed handle, the records |
| `Platform/` | DPAPI secrets, the vault file, Windows Hello, the clipboard |
| `Sync/` | The providers and the round that drives them |
| `Views/` | The pages and dialogs |
| `AppModel.cs` | The one piece of state; owns the only `VaultHandle` |

Every change goes through `AppModel.Mutate`, which seals the vault and writes
it. That is what stops a code path from leaving a change in memory only.

## Decisions worth knowing

**DPAPI is not hardware-backed, and the README should say so rather than imply
parity.** On Apple the key is in the Keychain and on Android in the Keystore,
both backed by hardware that will not export a key. Windows has no equivalent
available to an unprivileged desktop app, so the key is protected with DPAPI
for the current user: another Windows account cannot unprotect it, and a copied
profile is useless, but anything running as the signed-in user can. On Windows,
therefore, the lock is what stands between a signed-in session and the codes,
and the vault is as safe as the Windows account. That is a real difference in
the security model, not a detail.

**The lock is `UserConsentVerifier`** — Windows Hello's face, fingerprint or
PIN, ending at the account password. So the vault's own PIN is not the unlock
here either; it guards revealing a setup link and exporting a backup. Same
conclusion as Apple and Android, and the same open question: the app's PIN may
be worth dropping from the product, since all four platforms already have a
better one.

**The copied code is kept out of clipboard history and out of cloud roaming.**
Without that, Windows would keep the code after we cleared it and sync it to
the user's other machines — which is exactly what spec §4 is trying to prevent.
Clearing itself is a timer, so Settings says "while MFA is still running"
rather than promising more.

**One timer for the window, not one per row.** The list is a pure function of
the vault and the time, so the window re-reads it once a second and the
countdown rings cannot drift away from the codes they describe.

**No camera flow.** A webcam pointed at a screen is worse than reading the
picture, and it would mean asking for the webcam capability. QR codes come from
an image file through the core's decoder.

## What is not done

- **No tests.** The parts worth testing are DPAPI round-tripping and the sync
  providers; both want a Windows runner.
- **No QR image is drawn** for "move this account elsewhere" — the dialog shows
  the `otpauth://` link instead. The core can read a QR code but not draw one;
  drawing one needs a Windows encoder or a small addition to the core.
- No drag-to-reorder: `Reorder` is on the model but the list has no drag
  handle.
- No migration screen. `ImportMigration` is wired up and a migration QR in a
  picture is handled, but there is no step-by-step "scan code 2 of 3" flow as
  there is on mobile.
- The `otpauth` protocol handler is declared in the manifest but
  `OnLaunched` does not read the activation arguments yet.
- No app icon, no localisation, no MSIX signing, no installer.
