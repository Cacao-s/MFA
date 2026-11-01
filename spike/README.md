# Step 0 — the platform spike

Plan step 0 exists because the whole project rests on three platform
capabilities that no amount of shared code can provide.

**What this is for has changed since it was written.** The stack is decided —
native UI per platform over the Rust core (spec §2) — so these are no longer
plugin gaps that might sink the plan; they are first-party APIs with published
documentation. That turns step 0 from "find out whether this is possible" into
"confirm it behaves as documented, on real hardware, before building on it".
It is still the gate: a capability that does not actually work the way the
security model assumes (spec §4) is worth knowing about now rather than after
three UIs depend on it.

The shells to confirm it in already exist, so there is nothing to scaffold:
run each platform's app and exercise the five capabilities through it.

**This cannot be run in CI or in a container.** It needs a Mac, an iPhone, an
Android phone and a Windows machine, with real biometric hardware and a real
camera. Run it by hand and record what happened.

## What has to be proven

Three things, on each of macOS, iOS, Android and Windows:

| # | Capability | Done when |
|---|---|---|
| 1 | **Secure storage** | A 32-byte key is written, the app is force-quit and relaunched, and the same 32 bytes come back. Then: the key is *not* readable by another app or by reading app files off the device. |
| 2 | **Biometrics** | A prompt appears, succeeding returns success, cancelling returns cancelled, and a biometric failure is distinguishable from a cancel so the PIN fallback can be offered. |
| 3 | **QR input** | Mobile: the camera reads an `otpauth://` QR code from a screen. Desktop: a PNG or screen grab is read from a file. |

Plus two that the acceptance criteria depend on and that are easy to get wrong
per platform:

| # | Capability | Done when |
|---|---|---|
| 4 | **Background blanking** | The code is not visible in the app switcher thumbnail (spec §4). **Two platforms have nothing to test yet:** macOS and Windows have no blanking at all — iOS has `SceneBlanking` and Android sets `FLAG_SECURE`, but the desktop shells were written without it. On Windows that is `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`; on macOS, whether it is needed at all is a judgement about window previews and screen sharing rather than a switcher thumbnail. Decide and record it, because spec §4 currently promises it everywhere. |
| 5 | **Clipboard clearing** | A copied code is gone from the clipboard after 30 seconds, or the platform is recorded as unable to do it. |

## The contract to implement against

The core already defines what each capability has to look like, in
[`crates/mfa-core/src/platform.rs`](../crates/mfa-core/src/platform.rs):

- `SecureStore` — capability 1. This is the one that must not be faked with a
  file: the security model in spec §4 rests on the OS holding the key.
- `BiometricAuth` — capability 2, including the three-way `AuthOutcome` that
  capability 2's "done when" is really testing.
- `QrScanner` — capability 3 on mobile. On desktop, `mfa_core::qr` already
  decodes an image; the spike only has to get the bytes.
- `VaultStorage`, `Clipboard`, `SyncProvider` — the rest of the platform
  surface, for reference.

Each platform already implements them, which is what to exercise:

| Capability | Apple | Android | Windows |
|---|---|---|---|
| Secure storage | `apple/Sources/Platform/KeychainStore.swift` | `android/…/platform/KeystoreSecrets.kt` | `windows/MFA/Platform/ProtectedSecrets.cs` |
| Biometrics | `apple/Sources/Platform/Biometrics.swift` | `android/…/platform/Biometrics.kt` | `windows/MFA/Platform/WindowsHello.cs` |
| QR input | `apple/Sources/iOS/CameraScannerView.swift`, `apple/Sources/macOS/ScreenQR.swift` | `android/…/platform/QrAnalyzer.kt` | `mfa_core::qr` over a file |
| Background blanking | `apple/Sources/iOS/SceneBlanking.swift` (iOS only) | `android/…/MainActivity.kt` (`FLAG_SECURE`) | **not implemented** |
| Clipboard clearing | `apple/Sources/Platform/Clipboard.swift` | `android/…/platform/ClipboardCopier.kt` | `windows/MFA/Platform/ClipboardCopier.cs` |

Proving a capability some other way is fine too, as long as the result says
how it was proved.

## Expected sharp edges

Recorded here so the spike aims at them rather than discovering them late:

- **macOS / Windows biometrics.** Touch ID on macOS and Windows Hello are the
  two reached least often and with the least sample code behind them. Prove
  these first — in particular that a cancel is distinguishable from a failure,
  because the PIN fallback depends on telling them apart.
- **Desktop secure storage.** macOS Keychain and Windows DPAPI / Credential
  Manager behave nothing like each other. Confirm the DPAPI case really is
  bound to the user and not merely to the machine.
- **Android Keystore and app backup.** Confirm the key survives an OS update
  and that `allowBackup` does not quietly copy it anywhere.
- **iOS Keychain accessibility.** `WhenUnlockedThisDeviceOnly` keeps the key
  off iCloud backups. Confirm the key does *not* restore onto a second device,
  which is the behaviour we want.
- **Three implementations, one contract.** Each capability is now written
  three times, so the thing to watch for is the platforms disagreeing — a
  cancel reported as a failure on one of them, or a clipboard that silently
  never clears. `crates/mfa-core/src/platform.rs` is the contract all three
  are supposed to meet.

## Recording the result

One file per platform in `results/`, named `macos.md`, `ios.md`, `android.md`,
`windows.md`. Copy `results/TEMPLATE.md`. Attach a screen recording or
screenshots per capability.

`results/` is gitignored apart from the template, because a real run involves
real accounts.

When all four are done, write the conclusion into spec §2. If something
cannot be done, say so there too — that is a result, not a failure, and it is
the kind that changes the plan while changing it is still cheap.
