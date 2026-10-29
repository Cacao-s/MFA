# mfa-ffi

Makes `mfa-core` callable from the platform shells. Two surfaces over one
implementation:

| Surface | For | How |
|---|---|---|
| **UniFFI** | Swift (macOS, iOS), Kotlin (Android) | generated typed bindings — `make bindings` |
| **JSON over the C ABI** | Windows / C#, and anything else | two exported functions, `include/mfa_ffi.h` |

Both go through `VaultHandle`, so there is one set of rules and one place a bug
can live.

## Generating the bindings

```sh
make bindings          # bindings/swift/ and bindings/kotlin/
```

They are generated from the compiled library, so they cannot drift from it, and
they are gitignored: regenerate rather than edit.

For a packaged build:

```sh
./scripts/build-apple.sh   --release   # XCFramework + Swift, needs macOS + Xcode
./scripts/build-android.sh --release   # jniLibs + Kotlin, needs the NDK + cargo-ndk
```

Neither script has been run: they were written on a machine with no Xcode and
no NDK. Expect to fix a path or two on the first go.

## What the platform is responsible for

Everything the core deliberately does not do:

| Thing | Why it is yours |
|---|---|
| The data key, in the OS secure store | The security model rests on the OS holding it, not us |
| Reading and writing the vault file | Write atomically: temporary file, then rename |
| The clock | Every call takes `now_ms` or `now_secs`, so behaviour is reproducible and testable |
| Network calls for sync | You fetch the bytes, call `sync`, write back what it returns |
| Biometrics, camera, clipboard | Platform APIs; `mfa_core::platform` says what each has to guarantee |

A session is the same shape everywhere:

1. Read the data key from the secure store, or `generateDataKey()` on first run
   — and store it **before** sealing a vault with it, or the file cannot be
   read again.
2. `VaultHandle.open(dataKey, file)`, or `.create(dataKey)` if there is no file.
3. Call methods. After anything that changes the vault, call `seal()` and write
   the bytes back.

## Swift

```swift
import MfaCore

let key = try secureStore.dataKey() ?? {
    let fresh = generateDataKey()
    try secureStore.store(fresh)          // before sealing, not after
    return fresh
}()

let vault = try vaultFile.map { try VaultHandle.open(dataKey: key, file: $0) }
         ?? VaultHandle.create(dataKey: key)

// Adding a scanned QR code, having asked first if it is already there.
if try vault.duplicateOfUri(uri: scanned) == nil {
    _ = try vault.addUri(uri: scanned, nowMs: Int64(Date().timeIntervalSince1970 * 1000))
    try write(vault.seal())
}

// The list, re-read each second; `code` and `remainingSecs` are for the
// moment you asked about.
for account in try vault.accounts(nowSecs: UInt64(Date().timeIntervalSince1970)) {
    print(account.displayName, account.code, account.remainingSecs)
}
```

Errors arrive as `MfaError.Failed(kind:message:)`. Branch on `kind` and show
`message`: `.wrongPassword` means ask again, `.badFile` means do not.

## Kotlin

```kotlin
import com.zeyanlin.mfa.core.*

val vault = file?.let { VaultHandle.open(key, it) } ?: VaultHandle.create(key)
vault.addUri(scanned, System.currentTimeMillis())
write(vault.seal())

vault.accounts(System.currentTimeMillis() / 1000).forEach { account ->
    render(account.displayName, account.code, account.remainingSecs)
}
```

Add JNA with the `aar` artifact, or the bindings will not find the library:

```kotlin
implementation("net.java.dev.jna:jna:5.14.0@aar")
```

## Windows / C#

Two `DllImport`s and a JSON round trip. The method names, parameters and
results are the same ones, in `snake_case`; `src/capi.rs` documents them.

```csharp
internal static partial class Mfa
{
    [LibraryImport("mfa_ffi", StringMarshalling = StringMarshalling.Utf8)]
    private static partial IntPtr mfa_call(string requestJson);

    [LibraryImport("mfa_ffi")]
    private static partial void mfa_string_free(IntPtr responseJson);

    public static JsonDocument Call(string requestJson)
    {
        var handle = mfa_call(requestJson);
        try
        {
            var text = Marshal.PtrToStringUTF8(handle)!;
            return JsonDocument.Parse(text);
        }
        finally
        {
            mfa_string_free(handle);   // the caller always owns the result
        }
    }
}
```

```csharp
// {"ok": {"handle": 1}}
var opened = Mfa.Call("""{"method":"create","params":{"data_key":"Aq8…"}}""");

// {"ok": [{"id":"…","display_name":"Example (alice)","code":"123456", …}]}
var list = Mfa.Call($"""{{"method":"accounts","handle":1,"params":{{"now_secs":{now}}}}}""");
```

An open vault is a `handle`, an opaque integer; call `close` when the UI is
done with it. A failure comes back as
`{"error": {"kind": "WrongPassword", "message": "…"}}` — the same kinds Swift
and Kotlin get.

Byte arrays are Base64 strings, which is what a C# `byte[]` serialises to by
default — so `JsonSerializer` needs no converter for them. A JSON array of
numbers is accepted on input too, for a hand-written client that sends the
obvious thing. Both directions are pinned by tests, because it is a wire
contract with a client we cannot see.

### Why not generated C# bindings

UniFFI has no first-party C# generator. A third-party one exists, but it has to
track UniFFI's internal ABI, and a mismatch there is the kind of bug that shows
up as memory corruption rather than a compile error. Two hand-written functions
carrying JSON cannot fail that way, and the whole surface is reviewable in one
sitting.

## Tests

```sh
cargo test -p mfa-ffi --all-features
```

`tests/session.rs` drives the same functions the generated bindings call, so
what passes there is what the shells see; the only thing not covered is the
generated glue itself. `tests/capi.rs` covers the JSON bus, including the
pointer path a C caller takes and what happens on a null pointer, a double
close and bad parameters.
