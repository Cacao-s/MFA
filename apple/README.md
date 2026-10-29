# MFA for macOS and iOS

SwiftUI, one codebase for both. The core is Rust, reached through the generated
Swift bindings.

> **None of this has been compiled.** It was written on a machine with no Xcode.
> Expect to fix things on the first build — a missing import, a `Sendable`
> complaint, a signing setting. The shape and the decisions are the useful part;
> the compiler will have opinions about the rest.

## Building

```sh
# 1. The core, as an XCFramework plus the Swift bindings.
./scripts/build-apple.sh --release

# 2. The project. A .pbxproj is a blob nobody can review, so it is generated.
brew install xcodegen
cd apple && xcodegen generate && open MFA.xcodeproj
```

Two targets: `MFA-iOS` and `MFA-macOS`, sharing everything in
`Sources/{App,Platform,Sync,Views}` and differing only in `Sources/iOS` and
`Sources/macOS`.

The generated `MfaCore.swift` is compiled **into the app target** rather than
imported as a module. UniFFI emits its error enum without `public`, so from a
separate module `MfaError` would be invisible and nothing could read a
failure's kind.

## Layout

| Path | What |
|---|---|
| `Sources/App` | `MFAApp`, `AppModel`, and the lock settings mirror |
| `Sources/Platform` | Keychain, biometrics, the vault file, the clipboard |
| `Sources/Sync` | The providers and the round that drives them |
| `Sources/Views` | Every screen |
| `Sources/iOS` | Camera scanner, app-switcher blanking |
| `Sources/macOS` | QR from an image file or a screen grab |

`AppModel` owns the only `VaultHandle` in the app, and every change goes through
its `mutate`, which seals and writes. That is what stops a code path from
leaving a change in memory only.

## Decisions worth knowing

**The app lock is the OS's, not ours.** `LAContext` with
`.deviceOwnerAuthentication` — Face ID or Touch ID, falling back to the device
passcode. So the vault's PIN is *not* what unlocks the app here. The spec asks
for a PIN as the biometric fallback, and on Apple platforms the device passcode
already is that fallback, and is better: it is rate-limited by the Secure
Enclave, where ours would be four digits checked in our own process.

The PIN is still set and stored (it travels to the other platforms through the
vault); here it guards the few actions that deserve a second ask — revealing a
secret key, exporting a backup.

**Worth raising:** by the same argument the PIN is redundant on Android
(BiometricPrompt with `DEVICE_CREDENTIAL`) and on Windows (Hello falls back to a
PIN of the user's own). It may be worth dropping it from the product entirely
rather than maintaining a weaker copy of something all four platforms already
have.

**The Keychain items have no access control list.** `WhenUnlockedThisDeviceOnly`
keeps them out of iCloud Keychain and out of device backups, so restoring a
backup onto a new phone does not bring the accounts with it — moving device goes
through the encrypted backup or a sync target, which ask for the password. But
no `SecAccessControl`: with `.biometryCurrentSet` a user who adds a fingerprint
loses their vault, and with `.userPresence` every save would prompt.

**Two keys, two jobs.** The vault key is per-device and never leaves the
Keychain. The sync key is shared by the whole sync set and is published once,
wrapped in the user's backup password, as `mfa-sync.key` on the targets.

**The list is recomputed once a second**, from the core, with the current time
passed in. One timer for the whole screen, and a countdown ring that cannot
drift away from the code it is describing.

**The clipboard differs by platform, and the UI says so.** iOS hands the expiry
to the system, so a copied code disappears even if the app is killed. macOS has
no such facility, so it is a timer that checks nothing else has been copied
since — and Settings says "while MFA is still running" there rather than
promising more.

**Deleting an account asks twice** and says what the consequence is. It is the
one destructive action in the app that cannot be undone from the device itself.

## What is not done

- No app icon or asset catalog. Add `Resources/Assets.xcassets` and a
  `project.yml` entry.
- No localisation: the strings are inline English. They are written to be
  translated, not to stay like that.
- No Apple Watch, no widgets, no App Intents — out of scope for v1 (spec §1).
- `ScreenQR.captureScreenArea` is written but not wired to a menu item.
- The macOS target has no menu bar extra. A code you reach from the menu bar
  would suit this app, but it is not in v1.
