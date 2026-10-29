//! The optional self-hosted sync server (spec §3).
//!
//! It stores ciphertext and nothing else: the vault is encrypted with a key
//! the server never sees, so running one is no more trusted than putting the
//! file in a cloud drive. That is the point — self-hosting is an option, not a
//! privileged position.
//!
//! **There is no account system, by decision.** One user, one bearer token.
//! No registration, no password reset, no recovery flow: those are the
//! operational costs that made a hosted service the thing we were avoiding,
//! and somebody self-hosting can change the token themselves.
//!
//! # The API
//!
//! ```text
//! GET  /v1/health                 is it up (no auth, says nothing else)
//! GET  /v1/files/{name}           the blob, with an ETag
//! PUT  /v1/files/{name}           store the blob, guarded by If-Match
//! ```
//!
//! A client reads, merges locally and writes back, quoting the ETag it read:
//!
//! - `If-Match: "<etag>"` — write only if the blob is still at that revision.
//!   A mismatch is `412 Precondition Failed`, and the client should re-read,
//!   merge again and retry rather than overwrite.
//! - `If-None-Match: *` — write only if the blob does not exist yet. An
//!   existing blob is `412`.
//! - A write to an existing blob with neither header is `428 Precondition
//!   Required`. The server will not take an unguarded overwrite of a vault,
//!   because a client that forgot the header is a client that is about to
//!   lose someone's accounts.
//!
//! The blob is opaque, but the server does check that it looks like one of
//! ours (an `MFA` container of plausible length), so the endpoint cannot be
//! used as a general-purpose file host by anyone who gets the token.

pub mod store;

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

use crate::store::Store;

/// Largest blob we accept. A vault is kilobytes; this is room to grow without
/// letting the endpoint be used as a dumping ground.
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Shortest token the server will start with.
pub const MIN_TOKEN_LEN: usize = 32;

/// Smallest body that could be one of our containers.
const MIN_BLOB_BYTES: usize = 32;

#[derive(Debug)]
pub struct AppState {
    token: String,
    store: Store,
    /// Serialises read-compare-write so two simultaneous writes cannot both
    /// pass the `If-Match` check. A single-user server has no need for
    /// anything finer.
    write_lock: Mutex<()>,
}

impl AppState {
    /// Fails if the token is too short to be worth having.
    pub fn new(token: String, store: Store) -> Result<Self, ConfigError> {
        if token.len() < MIN_TOKEN_LEN {
            return Err(ConfigError::TokenTooShort {
                need: MIN_TOKEN_LEN,
                got: token.len(),
            });
        }
        Ok(Self {
            token,
            store,
            write_lock: Mutex::new(()),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("the sync token must be at least {need} characters, got {got}")]
    TokenTooShort { need: usize, got: usize },
}

/// Builds the router.
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/files/{name}", get(get_file).put(put_file))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    // Deliberately says nothing about the version or the contents.
    (StatusCode::OK, "ok")
}

async fn get_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Response, ApiError> {
    authorize(&state, &headers)?;
    let name = blob_name(&name)?;

    let Some(stored) = state.store.get(name).await.map_err(ApiError::storage)? else {
        return Err(ApiError::NotFound);
    };

    // A client that already has this revision does not need the bytes again.
    if let Some(requested) = headers.get(header::IF_NONE_MATCH) {
        if etag_matches(requested.as_bytes(), &stored.etag) {
            return Ok((StatusCode::NOT_MODIFIED, etag_header(&stored.etag)).into_response());
        }
    }

    Ok((
        StatusCode::OK,
        etag_header(&stored.etag),
        [(header::CONTENT_TYPE, "application/octet-stream")],
        stored.bytes,
    )
        .into_response())
}

async fn put_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    body: Bytes,
) -> Result<Response, ApiError> {
    authorize(&state, &headers)?;
    let name = blob_name(&name)?;

    if body.len() < MIN_BLOB_BYTES || !body.starts_with(b"MFA") {
        return Err(ApiError::NotOurFormat);
    }

    let _guard = state.write_lock.lock().await;
    let current = state.store.get(name).await.map_err(ApiError::storage)?;

    let if_match = headers.get(header::IF_MATCH);
    let if_none_match = headers.get(header::IF_NONE_MATCH);

    // RFC 9110 order: If-Match, then If-None-Match. Both have to pass.
    if let Some(requested) = if_match {
        // Nothing stored means nothing to match, `*` included.
        let passes = current
            .as_ref()
            .is_some_and(|stored| etag_matches(requested.as_bytes(), &stored.etag));
        if !passes {
            return Err(ApiError::PreconditionFailed);
        }
    }
    if let Some(requested) = if_none_match {
        let passes = !current
            .as_ref()
            .is_some_and(|stored| etag_matches(requested.as_bytes(), &stored.etag));
        if !passes {
            return Err(ApiError::PreconditionFailed);
        }
    }
    // A first write needs no guard: there is nothing to lose. An overwrite
    // does, because a client that forgot the header is a client about to lose
    // someone's accounts.
    if current.is_some() && if_match.is_none() && if_none_match.is_none() {
        return Err(ApiError::PreconditionRequired);
    }

    let etag = state
        .store
        .put(name, &body)
        .await
        .map_err(ApiError::storage)?;

    Ok((StatusCode::NO_CONTENT, etag_header(&etag)).into_response())
}

fn etag_header(etag: &str) -> [(header::HeaderName, String); 1] {
    [(header::ETAG, format!("\"{etag}\""))]
}

/// Compares an `If-Match` / `If-None-Match` value against a stored ETag.
///
/// Accepts the quoted form, the bare hex a hand-rolled client might send, and
/// `*`, and tolerates a comma-separated list.
fn etag_matches(requested: &[u8], stored: &str) -> bool {
    let Ok(requested) = core::str::from_utf8(requested) else {
        return false;
    };
    requested.split(',').any(|candidate| {
        let candidate = candidate.trim().trim_start_matches("W/").trim_matches('"');
        candidate == "*" || candidate == stored
    })
}

/// Checks the bearer token in constant time.
fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;

    let matches: bool = presented.as_bytes().ct_eq(state.token.as_bytes()).into();
    if matches {
        Ok(())
    } else {
        Err(ApiError::Unauthorized)
    }
}

/// Validates a blob name.
///
/// Only a flat, boring name: no directory separators, no leading dot, so
/// nothing can reach outside the data directory or land on a hidden file.
fn blob_name(name: &str) -> Result<&str, ApiError> {
    let acceptable = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));

    if acceptable {
        Ok(name)
    } else {
        Err(ApiError::BadName)
    }
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    BadName,
    NotOurFormat,
    NotFound,
    PreconditionFailed,
    PreconditionRequired,
    Storage,
}

impl ApiError {
    fn storage(error: std::io::Error) -> Self {
        // Logged here, never sent to the client: the path layout and the
        // reason are no business of whoever is holding the token.
        tracing::error!(%error, "storage failure");
        ApiError::Storage
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::BadName => (StatusCode::BAD_REQUEST, "bad file name"),
            ApiError::NotOurFormat => (StatusCode::BAD_REQUEST, "not an MFA file"),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found"),
            ApiError::PreconditionFailed => (
                StatusCode::PRECONDITION_FAILED,
                "the file moved on; re-read, merge and retry",
            ),
            ApiError::PreconditionRequired => (
                StatusCode::PRECONDITION_REQUIRED,
                "an overwrite needs If-Match",
            ),
            ApiError::Storage => (StatusCode::INTERNAL_SERVER_ERROR, "storage failure"),
        };
        (status, message).into_response()
    }
}
