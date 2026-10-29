//! Two devices syncing real vaults through the server.
//!
//! This is the test that ties the two crates together: it proves the server's
//! ETag contract is actually the one `mfa_core::sync` needs, including the
//! case that matters most — a write that lost a race has to re-read, merge
//! again and retry, never overwrite.
//!
//! `sync_once` below is deliberately written as a platform shell would write
//! it, so it doubles as the reference for the Swift, Kotlin and C# sides.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt as _;
use mfa_core::sync::{self, RemoteState, SyncKey};
use mfa_core::{OtpauthUri, Uuid, Vault};
use mfa_sync_server::store::Store;
use mfa_sync_server::{app, AppState};
use tokio::runtime::Runtime;
use tower::ServiceExt as _;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const NAME: &str = "mfa-sync.vault";
const T0: i64 = 1_700_000_000_000;

/// The server, plus the runtime the blocking helpers drive it with.
///
/// The test is a plain `#[test]` so that these helpers can block: a platform
/// shell has the same boundary to cross, in its own idiom.
struct TestServer {
    app: Router,
    runtime: Runtime,
    _directory: tempfile::TempDir,
}

impl TestServer {
    fn start() -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let state = AppState::new(TOKEN.to_owned(), Store::new(directory.path()))
            .expect("the test token is long enough");
        Self {
            app: app(Arc::new(state)),
            runtime: Runtime::new().expect("a tokio runtime"),
            _directory: directory,
        }
    }

    /// Downloads the blob and its revision, or `None` if it is not there.
    fn fetch(&self, name: &str) -> Option<(Vec<u8>, String)> {
        self.runtime.block_on(async {
            let response = self
                .app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/v1/files/{name}"))
                        .header("authorization", format!("Bearer {TOKEN}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            if response.status() == StatusCode::NOT_FOUND {
                return None;
            }
            assert_eq!(response.status(), StatusCode::OK);
            let revision = response
                .headers()
                .get("etag")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .expect("a stored blob has a revision");
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            Some((bytes.to_vec(), revision))
        })
    }

    /// Uploads, guarded by the revision that was read. `None` means "only if
    /// it does not exist yet".
    ///
    /// Returns `false` when the revision moved, which is the caller's cue to
    /// start over rather than overwrite.
    fn put_if_unchanged(&self, name: &str, bytes: &[u8], expected: Option<&str>) -> bool {
        self.runtime.block_on(async {
            let request = Request::builder()
                .method("PUT")
                .uri(format!("/v1/files/{name}"))
                .header("authorization", format!("Bearer {TOKEN}"));
            let request = match expected {
                Some(revision) => request.header("if-match", revision),
                None => request.header("if-none-match", "*"),
            };

            let response = self
                .app
                .clone()
                .oneshot(request.body(Body::from(bytes.to_vec())).unwrap())
                .await
                .unwrap();

            match response.status() {
                StatusCode::NO_CONTENT => true,
                StatusCode::PRECONDITION_FAILED => false,
                other => panic!("unexpected status {other}"),
            }
        })
    }
}

/// One sync round: read, merge, write back, retrying if the remote moved.
///
/// Returns the merged vault and how many attempts it took.
fn sync_once(server: &TestServer, local: &Vault, key: &SyncKey) -> (Vault, usize) {
    let target = Uuid::new_v4();

    for attempt in 1..=5 {
        let fetched = server.fetch(NAME);
        let (remote_bytes, revision) = match &fetched {
            Some((bytes, revision)) => (Some(bytes.as_slice()), Some(revision.as_str())),
            None => (None, None),
        };

        let outcome = sync::reconcile_all(
            local,
            &[RemoteState {
                target,
                bytes: remote_bytes,
            }],
            key,
        )
        .expect("the remote file is ours");
        assert!(outcome.failures.is_empty());

        let Some(upload) = outcome.uploads.into_iter().next() else {
            // The remote already holds the merge; nothing to write.
            return (outcome.merged, attempt);
        };

        if server.put_if_unchanged(NAME, &upload.bytes, revision) {
            return (outcome.merged, attempt);
        }
        // Someone wrote in between. Round again, against what is there now.
    }
    panic!("the remote kept moving");
}

fn account(issuer: &str, name: &str) -> mfa_core::Account {
    OtpauthUri::parse(&format!(
        "otpauth://totp/{issuer}:{name}?secret=JBSWY3DPEHPK3PXP&issuer={issuer}"
    ))
    .expect("the test URI is well formed")
    .into()
}

#[test]
fn two_devices_converge_through_the_server() {
    let server = TestServer::start();
    let key = sync::new_sync_key();

    // Both devices start from the same account, then each adds one offline.
    let mut shared = Vault::new();
    shared.add(account("Shared", "everyone"), T0);
    let mut device_a = shared.clone();
    let mut device_b = shared;
    device_a.add(account("From A", "a"), T0 + 1_000);
    device_b.add(account("From B", "b"), T0 + 2_000);

    let (merged_a, attempts) = sync_once(&server, &device_a, &key);
    device_a = merged_a;
    assert_eq!(attempts, 1, "the folder was empty");
    assert_eq!(device_a.len(), 2);

    let (merged_b, _) = sync_once(&server, &device_b, &key);
    device_b = merged_b;
    assert_eq!(device_b.len(), 3, "B picked up A's account");

    let (merged_a, _) = sync_once(&server, &device_a, &key);
    device_a = merged_a;
    assert_eq!(
        device_a.to_bytes().unwrap(),
        device_b.to_bytes().unwrap(),
        "both devices hold the same vault"
    );

    // And it settles: another round writes nothing.
    let (again, _) = sync_once(&server, &device_a, &key);
    assert_eq!(again.to_bytes().unwrap(), device_a.to_bytes().unwrap());
}

#[test]
fn a_write_that_lost_the_race_merges_instead_of_overwriting() {
    let server = TestServer::start();
    let key = sync::new_sync_key();

    let mut device_a = Vault::new();
    device_a.add(account("From A", "a"), T0);
    let mut device_b = Vault::new();
    device_b.add(account("From B", "b"), T0 + 1_000);

    // A publishes, and B reads that revision.
    let (device_a, _) = sync_once(&server, &device_a, &key);
    let (_, revision) = server.fetch(NAME).expect("A published");

    // A third device writes before B gets its write in, so B's revision is
    // now stale.
    let mut device_c = Vault::new();
    device_c.add(account("From C", "c"), T0 + 2_000);
    let (device_c, _) = sync_once(&server, &device_c, &key);

    // B's guarded write is refused, exactly as the client loop expects.
    let stale = sync::seal(&device_b, &key).unwrap();
    assert!(
        !server.put_if_unchanged(NAME, &stale, Some(&revision)),
        "a stale revision must not be accepted"
    );

    // Running the loop instead gets B's account in without losing A's or C's.
    let (device_b, attempts) = sync_once(&server, &device_b, &key);
    assert_eq!(attempts, 1);
    assert_eq!(device_b.len(), 3, "A, B and C are all there");

    // Everyone catches up to the same vault.
    let (device_a, _) = sync_once(&server, &device_a, &key);
    let (device_c, _) = sync_once(&server, &device_c, &key);
    let expected = device_b.to_bytes().unwrap();
    assert_eq!(device_a.to_bytes().unwrap(), expected);
    assert_eq!(device_c.to_bytes().unwrap(), expected);
}

#[test]
fn the_server_only_ever_holds_ciphertext() {
    let server = TestServer::start();
    let key = sync::new_sync_key();

    let mut device = Vault::new();
    device.add(account("Example", "alice@example.com"), T0);
    sync_once(&server, &device, &key);

    let (stored, _) = server.fetch(NAME).expect("something was published");

    // Nothing recognisable from the account is in the file.
    for needle in [
        b"Example".as_slice(),
        b"alice@example.com".as_slice(),
        b"JBSWY3DPEHPK3PXP".as_slice(),
        b"secret".as_slice(),
    ] {
        assert!(
            !stored.windows(needle.len()).any(|window| window == needle),
            "{} leaked into the stored file",
            String::from_utf8_lossy(needle)
        );
    }

    // And without the key it is not readable at all.
    assert!(sync::open(&stored, &sync::new_sync_key()).is_err());
}

#[test]
fn a_device_joins_with_the_sync_password() {
    // The key file lives on the same server, wrapped with the user's password
    // — the same password as the encrypted backup.
    let server = TestServer::start();
    let key = sync::new_sync_key();
    let password = "correct horse battery staple";

    let key_file = sync::wrap_key(&key, password, &Default::default()).unwrap();
    assert!(server.put_if_unchanged("mfa-sync.key", &key_file, None));

    let (fetched, _) = server.fetch("mfa-sync.key").expect("the key file is there");
    let on_new_device = sync::unwrap_key(&fetched, password).unwrap();

    // The new device can now read the vault the first one published.
    let mut first = Vault::new();
    first.add(account("Example", "alice"), T0);
    sync_once(&server, &first, &key);
    let (vault_file, _) = server.fetch(NAME).unwrap();
    assert_eq!(sync::open(&vault_file, &on_new_device).unwrap(), first);
}
