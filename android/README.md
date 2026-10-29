# MFA for Android

Jetpack Compose over the Rust core, reached through the generated Kotlin
bindings.

> **None of this has been compiled.** It was written on a machine with no
> Android SDK and no NDK. Expect to fix things on the first build — an import,
> a Compose API that moved, a Gradle version. The shape and the decisions are
> the useful part.

## Building

```sh
# 1. The core, as JNI libraries plus the Kotlin bindings.
cargo install cargo-ndk            # once
./scripts/build-android.sh --release

# 2. The app.
cd android && ./gradlew assembleDebug
```

`app/build.gradle.kts` points `jniLibs` and the Kotlin source set at
`../../build/android/`, which is where that script writes. There is no Gradle
wrapper checked in; run `gradle wrapper` once, or open the project in Android
Studio and let it add one.

JNA has to be the `@aar` artifact. The plain jar carries no Android native
libraries and the bindings then fail to load on first call, with an error that
does not mention JNA.

## Layout

| Path | What |
|---|---|
| `platform/` | Keystore, the vault file, biometrics, clipboard, QR analyser |
| `sync/` | The providers and the round that drives them |
| `ui/` | The view model and every screen |

`AppViewModel` owns the only `VaultHandle` in the app, and every change goes
through its `mutate`, which seals and writes. That is what stops a code path
from leaving a change in memory only.

## Decisions worth knowing

**The Keystore wrapping key is not bound to authentication.** It sounds
stronger and is a trap: `setUserAuthenticationRequired(true)` brings
`setInvalidatedByBiometricEnrollment` with it, so a user who adds a fingerprint
destroys the key and every account in the vault with it. Instead a plain,
non-exportable AES key wraps the core's keys, and the gate is `BiometricPrompt`
with `BIOMETRIC_STRONG or DEVICE_CREDENTIAL` — which already falls back to the
device PIN, so the app does not need a PIN of its own to be the fallback.

The vault's PIN is therefore a re-authentication step for revealing a secret or
exporting a backup, not the unlock. Same conclusion as on Apple, and the same
open question: it may be worth dropping from the product entirely rather than
maintaining a weaker copy of what all four platforms already have.

**`FLAG_SECURE` is set for the whole activity**, not toggled. It keeps the codes
out of the recent-apps thumbnail, out of screenshots and out of screen
recordings (spec §4); toggling it races the system's own snapshot.

**ZXing, not ML Kit.** ML Kit's barcode scanner pulls in Play Services. This app
does not talk to Google, and a QR decoder is not worth making it start. The
analyser reads only the luminance plane, inside one method, and keeps no frame.

**Backup and device transfer are off** in both the manifest and
`data_extraction_rules.xml`. The vault key cannot leave the Keystore, so a
transferred vault file would be unreadable anyway; excluding it keeps the
ciphertext from travelling for no benefit. Moving device goes through the
encrypted backup file or a sync target.

**`otpauth://` links open the app.** A browser or a password manager can hand an
account straight over, and one that arrives while the app is locked waits until
the vault is open rather than being dropped.

**One ticker, not one per row.** The list is recomputed once a second from the
core with the time passed in, so the countdown ring cannot drift away from the
code it is describing.

## What is not done

- **No tests.** The parts worth testing on-device are the Keystore wrapping and
  the sync providers; both want instrumentation tests, which need a device.
- No Gradle wrapper (see above), no signing config, no release keystore.
- The launcher icon is a placeholder vector.
- No localisation: strings are inline English, written to be extracted.
- No Wear OS, no widget, no quick-settings tile — out of scope for v1 (spec §1).
- Drag-to-reorder is not wired up on Android: `reorder` is there on the view
  model, but the list does not have a drag handle yet.
