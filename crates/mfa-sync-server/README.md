# mfa-sync-server

The optional self-hosted sync server. It stores ciphertext and nothing else.

The vault is encrypted with a key this server never sees, so running one is no
more trusted than putting the file in a cloud drive — which is the point:
self-hosting is an option, not a privileged position. The tests check this
directly, by looking for the account name and the secret in the stored bytes.

**There is no account system, by decision.** One user, one bearer token. No
registration, no password reset, no recovery flow: those are the operational
costs that made a hosted service the thing we were avoiding, and somebody
self-hosting can change the token themselves.

## Running it

```sh
export MFA_SYNC_TOKEN="$(openssl rand -hex 32)"
cargo run -p mfa-sync-server
```

| Variable | Meaning | Default |
|---|---|---|
| `MFA_SYNC_TOKEN` | the one bearer token, at least 32 characters | required |
| `MFA_SYNC_DATA` | where blobs are kept | `./data` |
| `MFA_SYNC_ADDR` | address to listen on | `127.0.0.1:8787` |

The default address is loopback on purpose. **Put it behind a reverse proxy
that terminates TLS**: the token is a bearer token, so over plain HTTP anyone
on the path can take it and then read and overwrite the vault file. They still
cannot decrypt it, but they can destroy it.

### Docker

```sh
docker build -f crates/mfa-sync-server/Dockerfile -t mfa-sync-server .
docker run -p 8787:8787 -v mfa-sync:/data \
  -e MFA_SYNC_TOKEN="$(openssl rand -hex 32)" mfa-sync-server
```

## The API

```
GET  /v1/health                 is it up (no auth, says nothing else)
GET  /v1/files/{name}           the blob, with an ETag
PUT  /v1/files/{name}           store the blob, guarded by If-Match
```

Two files are used in practice: `mfa-sync.vault` and `mfa-sync.key`.

A client reads, merges locally and writes back, quoting the ETag it read:

| Request | Meaning | On failure |
|---|---|---|
| `If-Match: "<etag>"` | write only if the blob is still at that revision | `412`, and the client re-reads, merges again and retries |
| `If-None-Match: *` | write only if the blob does not exist yet | `412` |
| neither, blob exists | — | `428`: an overwrite needs a guard |
| neither, blob absent | first write | allowed |

`GET` honours `If-None-Match` and answers `304` when the client is already
current.

The ETag is the hex SHA-256 of the content. Content-derived rather than a
counter, so two servers given the same file agree, and a restore from a
filesystem backup cannot reuse a revision for different content.

## Why it refuses things

- **A token under 32 characters**: the server will not start. Failing loudly
  beats running with something guessable.
- **An overwrite with no `If-Match`**: `428`. A client that forgot the header
  is a client about to lose someone's accounts.
- **A body that is not one of ours** (an `MFA` container of plausible length):
  `400`. Whoever holds the token should not be able to use this as a general
  file host.
- **A name with a separator, a leading dot, or anything outside
  `[A-Za-z0-9._-]`**: `400`. Nothing can reach outside the data directory.

Writes go to a temporary file and are renamed, so a crash or a full disk
cannot leave a half-written vault that no longer decrypts. Read-compare-write
is serialised by one lock, so two simultaneous writes cannot both pass the
`If-Match` check; a single-user server needs nothing finer.

## Tests

```sh
cargo test -p mfa-sync-server
```

`tests/api.rs` covers the HTTP contract. `tests/end_to_end.rs` drives real
vaults from `mfa-core` through the server — two devices converging, and a
write that lost a race re-reading and merging instead of overwriting. Its
`sync_once` is written as a platform shell would write it, so it doubles as
the reference for the Swift, Kotlin and C# sides.
