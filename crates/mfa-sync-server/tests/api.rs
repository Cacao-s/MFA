//! The sync server's HTTP contract.
//!
//! Driven through the router rather than a socket, so the suite needs no
//! network and no ports.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt as _;
use mfa_sync_server::store::Store;
use mfa_sync_server::{app, AppState, MAX_BODY_BYTES};
use tower::ServiceExt as _;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const NAME: &str = "mfa-sync.vault";

/// A server on a temporary directory, which is removed when the guard drops.
fn server() -> (Router, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let state = AppState::new(TOKEN.to_owned(), Store::new(directory.path()))
        .expect("the test token is long enough");
    (app(Arc::new(state)), directory)
}

/// Anything that passes the server's "is this one of ours" check.
fn blob(tag: u8) -> Vec<u8> {
    let mut bytes = b"MFASYNC1".to_vec();
    bytes.extend_from_slice(&[tag; 64]);
    bytes
}

struct Sent {
    status: StatusCode,
    etag: Option<String>,
    body: Bytes,
}

async fn send(app: &Router, request: Request<Body>) -> Sent {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("the router responds");
    let status = response.status();
    let etag = response
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim_matches('"').to_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Sent { status, etag, body }
}

fn authorized(method: &str, name: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(format!("/v1/files/{name}"))
        .header("authorization", format!("Bearer {TOKEN}"))
}

async fn put(app: &Router, name: &str, bytes: Vec<u8>, guards: &[(&str, &str)]) -> Sent {
    let mut request = authorized("PUT", name);
    for (key, value) in guards {
        request = request.header(*key, *value);
    }
    send(app, request.body(Body::from(bytes)).unwrap()).await
}

async fn get(app: &Router, name: &str, guards: &[(&str, &str)]) -> Sent {
    let mut request = authorized("GET", name);
    for (key, value) in guards {
        request = request.header(*key, *value);
    }
    send(app, request.body(Body::empty()).unwrap()).await
}

#[tokio::test]
async fn health_needs_no_token_and_says_nothing_else() {
    let (app, _directory) = server();
    let response = send(
        &app,
        Request::builder()
            .uri("/v1/health")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body.as_ref(), b"ok");
}

#[tokio::test]
async fn a_blob_round_trips() {
    let (app, _directory) = server();
    let content = blob(1);

    let written = put(&app, NAME, content.clone(), &[]).await;
    assert_eq!(written.status, StatusCode::NO_CONTENT);
    let etag = written.etag.expect("a write reports the new revision");

    let read = get(&app, NAME, &[]).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body.as_ref(), content.as_slice());
    assert_eq!(read.etag.as_deref(), Some(etag.as_str()));
}

#[tokio::test]
async fn without_a_token_nothing_is_readable_or_writable() {
    let (app, _directory) = server();
    put(&app, NAME, blob(1), &[]).await;

    for request in [
        Request::builder()
            .method("GET")
            .uri(format!("/v1/files/{NAME}")),
        Request::builder()
            .method("GET")
            .uri(format!("/v1/files/{NAME}"))
            .header("authorization", "Bearer wrong-token-wrong-token-wrong-to"),
        Request::builder()
            .method("GET")
            .uri(format!("/v1/files/{NAME}"))
            .header("authorization", TOKEN), // no "Bearer "
        Request::builder()
            .method("PUT")
            .uri(format!("/v1/files/{NAME}"))
            .header("authorization", "Bearer "),
    ] {
        let response = send(&app, request.body(Body::from(blob(2))).unwrap()).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }

    // And the stored blob is untouched.
    assert_eq!(get(&app, NAME, &[]).await.body.as_ref(), blob(1).as_slice());
}

#[tokio::test]
async fn a_missing_blob_is_not_found() {
    let (app, _directory) = server();
    assert_eq!(get(&app, NAME, &[]).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_overwrite_without_a_guard_is_refused() {
    // A client that forgot If-Match is a client about to lose someone's
    // accounts, so the server will not take the write.
    let (app, _directory) = server();
    put(&app, NAME, blob(1), &[]).await;

    let response = put(&app, NAME, blob(2), &[]).await;
    assert_eq!(response.status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(get(&app, NAME, &[]).await.body.as_ref(), blob(1).as_slice());
}

#[tokio::test]
async fn a_stale_revision_is_refused_and_changes_nothing() {
    let (app, _directory) = server();
    let first = put(&app, NAME, blob(1), &[]).await.etag.unwrap();

    // Someone else writes in between.
    let second = put(
        &app,
        NAME,
        blob(2),
        &[("if-match", &format!("\"{first}\""))],
    )
    .await
    .etag
    .unwrap();
    assert_ne!(first, second);

    // Our write still quotes the revision we read.
    let stale = put(
        &app,
        NAME,
        blob(3),
        &[("if-match", &format!("\"{first}\""))],
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert!(
        String::from_utf8_lossy(&stale.body).contains("re-read"),
        "the client needs to be told what to do"
    );
    assert_eq!(get(&app, NAME, &[]).await.body.as_ref(), blob(2).as_slice());

    // With the current revision it goes through.
    let fresh = put(
        &app,
        NAME,
        blob(3),
        &[("if-match", &format!("\"{second}\""))],
    )
    .await;
    assert_eq!(fresh.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn create_only_writes_when_there_is_nothing_there() {
    let (app, _directory) = server();

    let created = put(&app, NAME, blob(1), &[("if-none-match", "*")]).await;
    assert_eq!(created.status, StatusCode::NO_CONTENT);

    let again = put(&app, NAME, blob(2), &[("if-none-match", "*")]).await;
    assert_eq!(again.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(get(&app, NAME, &[]).await.body.as_ref(), blob(1).as_slice());
}

#[tokio::test]
async fn if_match_on_a_missing_blob_is_refused() {
    // There is nothing to match, `*` included.
    let (app, _directory) = server();

    for guard in ["\"whatever\"", "*"] {
        let response = put(&app, NAME, blob(1), &[("if-match", guard)]).await;
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
    }
}

#[tokio::test]
async fn a_client_that_is_already_current_gets_no_body() {
    let (app, _directory) = server();
    let etag = put(&app, NAME, blob(1), &[]).await.etag.unwrap();

    let unchanged = get(&app, NAME, &[("if-none-match", &format!("\"{etag}\""))]).await;
    assert_eq!(unchanged.status, StatusCode::NOT_MODIFIED);
    assert!(unchanged.body.is_empty());

    // A different revision still gets the bytes.
    let changed = get(&app, NAME, &[("if-none-match", "\"something-else\"")]).await;
    assert_eq!(changed.status, StatusCode::OK);
    assert_eq!(changed.body.as_ref(), blob(1).as_slice());
}

#[tokio::test]
async fn the_etag_is_derived_from_the_content() {
    // Content-derived rather than a counter, so a restore from a filesystem
    // backup cannot reuse a revision for different content.
    let (app, _directory) = server();
    let first = put(&app, NAME, blob(1), &[]).await.etag.unwrap();
    let back = put(
        &app,
        NAME,
        blob(1),
        &[("if-match", &format!("\"{first}\""))],
    )
    .await;
    assert_eq!(back.etag, Some(first));
}

#[tokio::test]
async fn a_name_cannot_reach_outside_the_data_directory() {
    let (app, _directory) = server();

    for name in ["..", "...", ".hidden", ".", "with%20space", &"x".repeat(65)] {
        let response = put(&app, name, blob(1), &[]).await;
        assert_eq!(
            response.status,
            StatusCode::BAD_REQUEST,
            "should reject the name {name:?}"
        );
    }

    // A name with a separator does not even reach the handler.
    let response = send(
        &app,
        authorized("PUT", "../../etc/passwd")
            .body(Body::from(blob(1)))
            .unwrap(),
    )
    .await;
    assert_ne!(response.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn the_endpoint_is_not_a_general_purpose_file_host() {
    // Whoever holds the token can only put our own files here.
    let (app, _directory) = server();

    for body in [
        b"this is not an MFA file at all, it is prose".to_vec(),
        b"MFA".to_vec(), // right prefix, far too short
        Vec::new(),
        vec![0u8; 64],
    ] {
        let response = put(&app, NAME, body, &[]).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn an_oversized_body_is_rejected() {
    let (app, _directory) = server();
    let mut huge = b"MFASYNC1".to_vec();
    huge.resize(MAX_BODY_BYTES + 1, 0);

    let response = put(&app, NAME, huge, &[]).await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[test]
fn a_short_token_stops_the_server_starting() {
    // Better to fail loudly at startup than to run with a guessable token.
    let directory = tempfile::tempdir().unwrap();
    let error = AppState::new("too-short".to_owned(), Store::new(directory.path()))
        .expect_err("a short token must be refused");
    assert!(error.to_string().contains("at least 32"));
}
