# Step 0 — the platform spike

Plan step 0 exists because the whole project rests on three platform
capabilities that no amount of shared code can provide. If one of them cannot
be done on one platform, the stack is wrong and it is far cheaper to find out
now.

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
| 4 | **Background blanking** | The code is not visible in the app switcher thumbnail (spec §4). |
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

A spike that implements these traits is worth keeping; one that proves the
capability some other way is fine too, as long as it is honest about it.

## Expected sharp edges

Recorded here so the spike aims at them rather than discovering them late:

- **macOS / Windows biometrics.** Tauri's official `biometric` plugin is
  mobile-only (spec §2), so Touch ID on macOS and Windows Hello have to be
  reached directly. Prove these two first: they are the likeliest reason to
  fall back to another stack.
- **Desktop secure storage.** Likewise mobile-only in the official plugins.
  macOS Keychain and Windows DPAPI / Credential Manager need their own
  bindings.
- **Android Keystore and app backup.** Confirm the key survives an OS update
  and that `allowBackup` does not quietly copy it anywhere.
- **iOS Keychain accessibility.** `WhenUnlockedThisDeviceOnly` keeps the key
  off iCloud backups. Confirm the key does *not* restore onto a second device,
  which is the behaviour we want.
- **WebView feel on mobile**, if the stack ends up being Tauri — not a
  capability, but the thing spec §2 flags as the UX risk.

## Recording the result

One file per platform in `results/`, named `macos.md`, `ios.md`, `android.md`,
`windows.md`. Copy `results/TEMPLATE.md`. Attach a screen recording or
screenshots per capability.

`results/` is gitignored apart from the template, because a real run involves
real accounts.

When all four are done, write the conclusion into spec §2 and pick the stack.
If something cannot be done, say so there too — that is a result, not a
failure.
