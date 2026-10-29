//! Runs the sync server.
//!
//! Configuration is entirely environment variables, so a container needs no
//! config file:
//!
//! | Variable | Meaning | Default |
//! |---|---|---|
//! | `MFA_SYNC_TOKEN` | the one bearer token, at least 32 characters | required |
//! | `MFA_SYNC_DATA` | where blobs are kept | `./data` |
//! | `MFA_SYNC_ADDR` | address to listen on | `127.0.0.1:8787` |
//!
//! The default address is loopback on purpose: put it behind a reverse proxy
//! that terminates TLS. The token is a bearer token, so it must not travel
//! over plain HTTP.

use std::sync::Arc;

use mfa_sync_server::store::Store;
use mfa_sync_server::{app, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mfa_sync_server=info".into()),
        )
        .init();

    let token = std::env::var("MFA_SYNC_TOKEN").map_err(|_| {
        "MFA_SYNC_TOKEN is not set. Generate one with:  openssl rand -hex 32".to_owned()
    })?;
    let data = std::env::var("MFA_SYNC_DATA").unwrap_or_else(|_| "./data".to_owned());
    let addr = std::env::var("MFA_SYNC_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());

    let store = Store::new(&data);
    store.prepare().await?;
    let state = Arc::new(AppState::new(token, store)?);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(address = %listener.local_addr()?, data = %data, "listening");

    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

/// Finishes in-flight requests on Ctrl-C rather than cutting a write short.
async fn shutdown() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "could not listen for shutdown");
        return;
    }
    tracing::info!("shutting down");
}
