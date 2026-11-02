# Cross-language conformance

`crates/mfa-core` is written once and shared. Everything *around* it is
written three times — once in Kotlin, once in Swift, once in C# — and nothing
but agreement by hand keeps the three the same.

The sharpest case is the sync provider. `mfa_core::platform::SyncProvider` is
three lines of contract: fetch returns the bytes and a revision or nothing,
put returns a new revision or nothing. The meaning is in what "nothing" means,
and that is decided by an HTTP status code:

| | means | and the coordinator |
|---|---|---|
| `absent` | nothing is stored yet | writes, create-only |
| `lost_race` | somebody wrote first | re-reads, merges, retries |
| `error` | something is wrong | reports it to the user |

Those three are not interchangeable. A target that reports a race as an error
stops syncing and says so once; a target that reports an error as a race
retries until it gives up and says nothing useful. The codes themselves are
not guessable either — GitLab answers `400` for a stale revision where the
self-hosted server answers `412`, and GitHub answers `422` for "already
exists" where a stale blob sha is `409`.

So the table lives in one file, and each language is checked against it.

## The vectors

[`vectors/sync-provider.json`](vectors/sync-provider.json) — 23 cases. Each
one gives the flavour, the operation, the scripted HTTP exchanges, the
requests the implementation is expected to make, and the outcome it must
produce. Half the assertions are about the *request*: whether a write carried
its guard, and which verb GitLab was given. An implementation that reads
responses correctly and builds requests wrongly fails in production and
nowhere else.

The `self_hosted` cases are not merely asserted. They are replayed against the
real server in
[`crates/mfa-sync-server/tests/conformance.rs`](../crates/mfa-sync-server/tests/conformance.rs),
so the table cannot drift away from what the server actually answers. A case
the server cannot be made to produce — a proxy that strips the `ETag`, say —
is listed there by name with the reason, and a test fails if a new case
appears in neither list.

## Who checks what, and what has actually run

| Implementation | Suite | Runs on | Has it run? |
|---|---|---|---|
| the server's own answers | `crates/mfa-sync-server/tests/conformance.rs` | anywhere | **yes** — 8 tests |
| `windows/MFA/Sync/HttpProvider.cs` | [`dotnet/`](dotnet) | anywhere .NET runs | **yes** — 24 tests |
| `apple/Sources/Sync/HTTPProvider.swift` | `apple/Tests/Conformance/` | needs macOS and Xcode | **yes** — 23 vectors |
| `android/…/sync/HttpProvider.kt` | `android/app/src/test/…/SyncProviderConformanceTest.kt` | needs the Android SDK | **not yet** |

The Swift suite earned its keep the first time it ran: eight cases failed,
all of them the same bug. `HTTPProvider` percent-encoded the GitLab file path
with `.alphanumerics` as the allowed set, which also encodes `-` and `.`, so
the name went out as `mfa%2Dsync%2Evault`. GitLab would have accepted it and
nobody would ever have noticed, but Kotlin's `URLEncoder` and C#'s
`EscapeDataString` both leave RFC 3986's unreserved characters alone. Three
implementations agreed by accident and the fourth did not; now the rule is
written down in all four.

Only the Kotlin suite is still unrun, for want of an Android SDK.

Both the Kotlin and the C# suites also assert something the vectors do not
describe: that an error message never contains the token. The token travels in
a header, and an error body can echo a request back.

## Running them

```sh
# the server's answers, and the whole Rust side
make test

# the Windows implementation, on any platform
dotnet test conformance/dotnet

# the Android implementation (needs the SDK; no emulator, Robolectric only)
cd android && ./gradlew :app:testDebugUnitTest --tests '*SyncProviderConformanceTest'

# the Apple implementation (needs macOS, Xcode and xcodegen)
cd apple && xcodegen generate && xcodebuild test -scheme MFAConformance -destination 'platform=macOS'
```

Neither the .NET nor the Swift suite needs the Rust core built: both compile
only the sources that import nothing but their platform's standard library.
The Kotlin one lives inside the app module, so it builds what that module
builds.

## What this does not cover

**The coordinator.** `SyncCoordinator` is also written three times (190, 178
and 204 lines) and holds the retry protocol: read every target, merge once,
write back the ones that are behind, re-round a target that lost the race, and
give up after three attempts. It is the obvious next thing to pin down, and it
is not pinned down here, because every copy of it needs the FFI layer — and
the Windows one also needs WinUI — so a test would need the Rust core built
for each platform first. The three were compared by hand and agree, including
the attempt limit. That is not a test.

**Anything above the provider on a real device.** A conformance suite says the
three implementations decide alike. It says nothing about whether the Keystore,
the Keychain or DPAPI behave as assumed, which is what `spike/` is for and
what no amount of this can replace.
