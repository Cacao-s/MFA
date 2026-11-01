# Security

MFA holds the secrets that get people into their accounts. A bug here is worth
more to an attacker than a bug in most software this size, so please report
one rather than demonstrating it.

Nothing has been released yet, so there are no supported versions: the only
version is the tip of `main`.

## Reporting

**Use GitHub's private vulnerability reporting** — the "Report a
vulnerability" button under this repository's Security tab. That keeps the
report out of public view until there is something to upgrade to.

If that is unavailable, open an issue saying only that you have a security
report and asking for a contact address. Please do not put the details in a
public issue, a pull request or a commit message.

This is a one-person project, so expect acknowledgement in days rather than
hours. You will get a reply either way, including if the answer is "that is
intended, and here is why".

## What is in scope

- `crates/mfa-core` — TOTP, the `otpauth://` and migration parsers, the vault
  document and its merge rule, the file container, backup, and the sync
  protocol.
- `crates/mfa-ffi` — the boundary the platform shells call across.
- `crates/mfa-sync-server` — the optional self-hosted server.
- The platform shells in `apple/`, `android/` and `windows/`, in particular
  their use of Keychain, Keystore, DPAPI, biometrics and the clipboard.

Especially welcome: anything that gets a secret out of the process, anything
that makes a parser panic or allocate without bound (they are fed by QR codes
from sites we do not control and by files from other people's disks), and
anything that makes two devices disagree about what the user deleted.

## What is already known, and decided

These are documented trade-offs, not findings. Say so if you think one is
wrong — that is a design argument, and worth having — but it is not a
vulnerability report.

- **The app-lock PIN has very little entropy.** Four to eight digits cannot be
  made strong by key derivation. What keeps an attacker out is the vault's
  data key living in the platform's secure store, behind the OS's own rate
  limiting and biometric gate. The PIN verifier exists so the PIN itself is
  never stored. See `crates/mfa-core/src/pin.rs`.
- **One password protects the backup file and every sync target's key file.**
  That is a deliberate choice (one password to remember), and the cost is that
  the password has more offline-attackable copies the more targets are
  enabled. Argon2id is therefore fixed at 64 MiB / 3 passes on every device,
  with no lighter preset for older phones.
- **A sync target is not trusted, a self-hosted server included.** It only
  ever holds ciphertext. The server is not a privileged position, which is why
  it has no account system.
- **A sync file we cannot decrypt is reported, never overwritten.** It may
  belong to someone else's sync set.
- **Secrets are in memory while the app is unlocked.** They are wiped on drop,
  redacted in debug output and compared in constant time, but an attacker who
  can read the process's memory has them.

## What is not in scope

- Dependency advisories with no exploitable path here — please report those
  upstream. A dependency advisory that *is* exploitable through this code is
  very much in scope.
- The platform capabilities step 0 has not confirmed yet (`spike/README.md`).
  Those are open questions, tracked as such.
- Social engineering, physical access to an unlocked device, or a device whose
  OS is already compromised.
