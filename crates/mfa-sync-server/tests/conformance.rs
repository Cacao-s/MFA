//! Checks the shared conformance vectors against the server they describe.
//!
//! `conformance/vectors/sync-provider.json` is the decision table the three
//! platform shells implement — what a status code means, and which header
//! guards a write. It is only worth anything if it matches what the server
//! actually answers, so every self-hosted case that can be reproduced is
//! replayed here against the real router.
//!
//! The cases that *cannot* be reproduced are listed explicitly rather than
//! quietly skipped, and the last test fails if a new self-hosted case appears
//! in neither list. A table nobody has to keep honest stops being one.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt as _;
use mfa_sync_server::store::Store;
use mfa_sync_server::{app, AppState};
use serde_json::Value;
use tower::ServiceExt as _;

const TOKEN: &str = "conformance-token-not-a-real-one";
const NAME: &str = "mfa-sync.vault";

/// Cases the real server cannot be made to produce, and why.
///
/// These describe a server that is not ours — one behind a proxy that strips
/// headers, or simply broken. The client still has to cope, so the case stays
/// in the table; it just cannot be confirmed from this side.
const NOT_REPRODUCIBLE: &[(&str, &str)] = &[
    (
        "self_hosted/fetch/no-etag",
        "the server always sends an ETag; this covers a proxy that strips it",
    ),
    (
        "self_hosted/fetch/server-error",
        "a 500 means the store failed, which cannot be induced through the router",
    ),
    (
        "self_hosted/put/no-etag-in-response",
        "likewise always sent; this covers a proxy that strips it",
    ),
];

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/vectors/sync-provider.json"
    );
    let text = std::fs::read_to_string(path).expect("the vectors are in the repository");
    serde_json::from_str(&text).expect("the vectors are valid JSON")
}

fn self_hosted_case_ids(vectors: &Value) -> Vec<String> {
    vectors["cases"]
        .as_array()
        .expect("cases is an array")
        .iter()
        .filter(|case| case["flavour"] == "self_hosted")
        .map(|case| case["id"].as_str().expect("an id").to_owned())
        .collect()
}

/// The status a case says the server answers with.
fn declared_status(vectors: &Value, id: &str) -> StatusCode {
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("no case {id}"));

    // The status of the last exchange: the one whose outcome is being named.
    let status = case["exchanges"]
        .as_array()
        .and_then(|exchanges| exchanges.last())
        .map(|exchange| exchange["response"]["status"].as_u64().expect("a status"))
        .expect("at least one exchange");

    StatusCode::from_u16(u16::try_from(status).unwrap()).expect("a real status")
}

fn server() -> (Router, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let state = AppState::new(TOKEN.to_owned(), Store::new(directory.path()))
        .expect("the conformance token is long enough");
    (app(Arc::new(state)), directory)
}

struct Answer {
    status: StatusCode,
    etag: Option<String>,
    body: Vec<u8>,
}

async fn send(app: &Router, request: Request<Body>) -> Answer {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let etag = response
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    Answer { status, etag, body }
}

fn request(method: &str, guards: &[(&str, &str)], body: Option<&[u8]>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("/v1/files/{NAME}"))
        .header("authorization", format!("Bearer {TOKEN}"));
    for (key, value) in guards {
        builder = builder.header(*key, *value);
    }
    builder
        .body(body.map_or_else(Body::empty, |bytes| Body::from(bytes.to_vec())))
        .unwrap()
}

/// What the vectors use as the stored blob.
fn blob(vectors: &Value) -> Vec<u8> {
    use data_encoding::BASE64;
    BASE64
        .decode(vectors["blob_base64"].as_str().unwrap().as_bytes())
        .expect("the vectors' blob is Base64")
}

#[tokio::test]
async fn a_stored_file_comes_back_with_an_etag() {
    let vectors = vectors();
    let (app, _directory) = server();
    let content = blob(&vectors);

    send(
        &app,
        request("PUT", &[("if-none-match", "*")], Some(&content)),
    )
    .await;
    let answer = send(&app, request("GET", &[], None)).await;

    assert_eq!(
        answer.status,
        declared_status(&vectors, "self_hosted/fetch/present")
    );
    assert!(
        answer.etag.is_some(),
        "the revision has to come from somewhere"
    );
    assert_eq!(answer.body, content);
}

#[tokio::test]
async fn a_file_that_was_never_written_is_a_404() {
    let vectors = vectors();
    let (app, _directory) = server();

    let answer = send(&app, request("GET", &[], None)).await;
    assert_eq!(
        answer.status,
        declared_status(&vectors, "self_hosted/fetch/absent")
    );
}

#[tokio::test]
async fn a_bad_token_is_a_401() {
    let vectors = vectors();
    let (app, _directory) = server();

    let answer = send(
        &app,
        Request::builder()
            .method("GET")
            .uri(format!("/v1/files/{NAME}"))
            .header("authorization", "Bearer not-the-token-at-all-but-long")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(
        answer.status,
        declared_status(&vectors, "self_hosted/fetch/unauthorized")
    );
}

#[tokio::test]
async fn a_create_only_write_succeeds_on_an_empty_target() {
    let vectors = vectors();
    let (app, _directory) = server();

    let answer = send(
        &app,
        request("PUT", &[("if-none-match", "*")], Some(&blob(&vectors))),
    )
    .await;

    assert_eq!(
        answer.status,
        declared_status(&vectors, "self_hosted/put/first-write")
    );
    assert!(answer.etag.is_some(), "the new revision has to come back");
}

#[tokio::test]
async fn a_write_guarded_by_the_current_revision_succeeds() {
    let vectors = vectors();
    let (app, _directory) = server();
    let content = blob(&vectors);

    let created = send(
        &app,
        request("PUT", &[("if-none-match", "*")], Some(&content)),
    )
    .await;
    let revision = created.etag.expect("an ETag");

    let mut updated = content.clone();
    updated.extend_from_slice(b" (edited)");
    let answer = send(
        &app,
        request("PUT", &[("if-match", &revision)], Some(&updated)),
    )
    .await;

    assert_eq!(
        answer.status,
        declared_status(&vectors, "self_hosted/put/guarded-write")
    );
}

#[tokio::test]
async fn a_write_guarded_by_a_stale_revision_is_the_race_the_client_retries() {
    let vectors = vectors();
    let (app, _directory) = server();
    let content = blob(&vectors);

    send(
        &app,
        request("PUT", &[("if-none-match", "*")], Some(&content)),
    )
    .await;

    let answer = send(
        &app,
        request(
            "PUT",
            &[("if-match", "\"not-the-current-one\"")],
            Some(&content),
        ),
    )
    .await;

    assert_eq!(
        answer.status,
        declared_status(&vectors, "self_hosted/put/lost-race"),
        "a client told to retry on this status will loop or give up if the \
         server answers something else"
    );
    // And nothing was overwritten.
    assert_eq!(send(&app, request("GET", &[], None)).await.body, content);
}

#[tokio::test]
async fn an_unguarded_overwrite_is_refused_as_a_client_bug() {
    let vectors = vectors();
    let (app, _directory) = server();
    let content = blob(&vectors);

    send(
        &app,
        request("PUT", &[("if-none-match", "*")], Some(&content)),
    )
    .await;
    let answer = send(&app, request("PUT", &[], Some(&content))).await;

    assert_eq!(
        answer.status,
        declared_status(&vectors, "self_hosted/put/precondition-required"),
        "this one has to be distinguishable from 412: a race is retried, a \
         missing guard is a bug to report"
    );
}

#[tokio::test]
async fn every_self_hosted_case_is_either_checked_here_or_explained() {
    // The point of this test: a case added to the table without deciding
    // whether the server can be made to produce it is a case nobody has
    // confirmed. Add it to one list or the other.
    let vectors = vectors();

    let checked = [
        "self_hosted/fetch/present",
        "self_hosted/fetch/absent",
        "self_hosted/fetch/unauthorized",
        "self_hosted/put/first-write",
        "self_hosted/put/guarded-write",
        "self_hosted/put/lost-race",
        "self_hosted/put/precondition-required",
    ];

    for id in self_hosted_case_ids(&vectors) {
        let covered = checked.contains(&id.as_str())
            || NOT_REPRODUCIBLE.iter().any(|(known, _)| *known == id);
        assert!(
            covered,
            "{id} is in the vectors but is neither replayed against the server \
             nor listed in NOT_REPRODUCIBLE with a reason"
        );
    }

    // And the other way: a list that still names a case nobody kept.
    let ids = self_hosted_case_ids(&vectors);
    for id in checked
        .iter()
        .chain(NOT_REPRODUCIBLE.iter().map(|(id, _)| id))
    {
        assert!(
            ids.iter().any(|known| known == id),
            "{id} is listed here but no longer in the vectors"
        );
    }
}
