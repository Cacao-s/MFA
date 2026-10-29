//! A JSON command bus over the C ABI, for platforms without a first-party
//! UniFFI generator — Windows and C# in particular.
//!
//! Two exported functions, so binding it is a few lines of `DllImport`
//! instead of a generated file nobody reviews:
//!
//! ```c
//! char *mfa_call(const char *request_json);  /* caller frees the result */
//! void  mfa_string_free(char *response_json);
//! ```
//!
//! Both sides are UTF-8 JSON:
//!
//! ```json
//! → {"method": "open", "params": {"data_key": "Aq8…", "file": "TUZBVkFVTFQ…"}}
//! ← {"ok": {"handle": 1}}
//!
//! → {"method": "accounts", "handle": 1, "params": {"now_secs": 1730000000}}
//! ← {"ok": [{"id": "…", "code": "123456", "remaining_secs": 12, …}]}
//!
//! → {"method": "import_backup", "handle": 1, "params": {"file": […], "password": "…"}}
//! ← {"error": {"kind": "WrongPassword", "message": "wrong password, or the file has been altered"}}
//! ```
//!
//! The method names, parameter names and result shapes are the ones in
//! [`crate::handle`] and [`crate::types`], in `snake_case`. Byte arrays are
//! Base64 strings, which is what a C# `byte[]` serialises to by default, so
//! the far side needs no converter; a JSON array of numbers is accepted on
//! input as well, for a hand-written client.
//!
//! An open vault is a `handle`, an opaque integer. Call `close` when the UI is
//! done with it, which drops the vault and its key.

use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{ErrorKind, MfaError};
use crate::handle::VaultHandle;
use crate::jsonbytes::Base64Bytes;
use crate::types::*;

/// The open vaults, by handle.
///
/// A handle rather than a pointer: a C# caller should not be holding a raw
/// Rust pointer, and an integer that has been closed can be rejected cleanly
/// instead of being dereferenced.
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

#[derive(Default)]
struct Registry {
    next: u64,
    open: HashMap<u64, Arc<VaultHandle>>,
}

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| Mutex::new(Registry::default()))
}

fn with_registry<T>(action: impl FnOnce(&mut Registry) -> T) -> T {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    action(&mut guard)
}

/// Handles a request. Returns a NUL-terminated JSON string the caller must
/// release with [`mfa_string_free`].
///
/// # Safety
///
/// `request` must be a NUL-terminated UTF-8 string, or null.
#[no_mangle]
pub unsafe extern "C" fn mfa_call(request: *const c_char) -> *mut c_char {
    // A panic must not unwind into the caller's frame, and a bug in here
    // should surface as an error the UI can show rather than as a crash in
    // somebody else's stack trace.
    let response = std::panic::catch_unwind(|| {
        if request.is_null() {
            return error_json(ErrorKind::Other, "the request pointer was null");
        }
        match unsafe { CStr::from_ptr(request) }.to_str() {
            Ok(text) => dispatch_text(text),
            Err(_) => error_json(ErrorKind::Other, "the request was not valid UTF-8"),
        }
    })
    .unwrap_or_else(|_| error_json(ErrorKind::Other, "an internal error occurred"));

    into_c_string(response)
}

/// Releases a string returned by [`mfa_call`].
///
/// # Safety
///
/// `response` must be a pointer returned by [`mfa_call`] and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn mfa_string_free(response: *mut c_char) {
    if !response.is_null() {
        drop(unsafe { CString::from_raw(response) });
    }
}

fn into_c_string(text: String) -> *mut c_char {
    // A JSON response has no interior NUL, but a stray one must not take the
    // process down.
    CString::new(text)
        .unwrap_or_else(|_| {
            CString::new(error_json(ErrorKind::Other, "the response was malformed"))
                .expect("this message has no NUL")
        })
        .into_raw()
}

/// The command bus, as a Rust function.
///
/// Public so the tests can exercise the same path the C ABI takes, without
/// going through pointers.
pub fn dispatch_text(request: &str) -> String {
    let parsed: core::result::Result<Request, _> = serde_json::from_str(request);
    let request = match parsed {
        Ok(request) => request,
        Err(error) => {
            return error_json(
                ErrorKind::Other,
                format!("the request was not valid: {error}"),
            )
        }
    };

    match dispatch(request) {
        Ok(value) => json!({ "ok": value }).to_string(),
        Err(error) => {
            let MfaError::Failed { kind, message } = error;
            error_json(kind, message)
        }
    }
}

fn error_json(kind: ErrorKind, message: impl Into<String>) -> String {
    json!({ "error": { "kind": kind, "message": message.into() } }).to_string()
}

#[derive(Deserialize)]
struct Request {
    method: String,
    #[serde(default)]
    handle: Option<u64>,
    #[serde(default)]
    params: Value,
}

/// A handle, as a result.
#[derive(Serialize)]
struct Opened {
    handle: u64,
}

fn dispatch(request: Request) -> crate::error::Result<Value> {
    let Request {
        method,
        handle,
        params,
    } = request;

    // Methods that do not need an open vault.
    match method.as_str() {
        "library_version" => return value(crate::library_version()),
        "generate_data_key" => return value(Base64Bytes(crate::generate_data_key())),
        "new_sync_key" => return value(Base64Bytes(crate::new_sync_key())),
        "create" => {
            let p: CreateParams = take(params)?;
            let opened = VaultHandle::create(p.data_key)?;
            return value(Opened {
                handle: with_registry(|registry| registry.insert(opened)),
            });
        }
        "open" => {
            let p: OpenParams = take(params)?;
            let opened = VaultHandle::open(p.data_key, p.file)?;
            return value(Opened {
                handle: with_registry(|registry| registry.insert(opened)),
            });
        }
        "close" => {
            let handle = handle.ok_or_else(missing_handle)?;
            return value(with_registry(|registry| {
                registry.open.remove(&handle).is_some()
            }));
        }
        "wrap_sync_key" => {
            let p: WrapKeyParams = take(params)?;
            return value(Base64Bytes(crate::wrap_sync_key(p.sync_key, p.password)?));
        }
        "unwrap_sync_key" => {
            let p: UnwrapKeyParams = take(params)?;
            return value(Base64Bytes(crate::unwrap_sync_key(p.key_file, p.password)?));
        }
        "preview_uri" => {
            let p: UriParams = take(params)?;
            return value(crate::preview_uri(p.uri)?);
        }
        "migration_progress" => {
            let p: UrisParams = take(params)?;
            return value(crate::migration_progress(p.uris)?);
        }
        "inspect_backup" => {
            let p: FileParams = take(params)?;
            return value(crate::inspect_backup(p.file)?);
        }
        #[cfg(feature = "qr-image")]
        "decode_qr_image" => {
            let p: ImageParams = take(params)?;
            return value(crate::decode_qr_image(p.image)?);
        }
        _ => {}
    }

    // Everything else acts on an open vault. Cloning the Arc out of the
    // registry means a long call does not hold the registry lock.
    let handle = handle.ok_or_else(missing_handle)?;
    let vault = with_registry(|registry| registry.get(handle))?;

    match method.as_str() {
        "seal" => value(Base64Bytes(vault.seal()?)),
        "count" => value(vault.count()),
        "accounts" => {
            let p: NowSecsParams = take(params)?;
            value(vault.accounts(p.now_secs)?)
        }
        "search" => {
            let p: SearchParams = take(params)?;
            value(vault.search(p.query, p.now_secs)?)
        }
        "code" => {
            let p: CodeParams = take(params)?;
            value(vault.code(p.id, p.now_secs)?)
        }
        "account_uri" => {
            let p: IdParams = take(params)?;
            value(vault.account_uri(p.id)?)
        }
        "add_uri" => {
            let p: AddUriParams = take(params)?;
            value(vault.add_uri(p.uri, p.now_ms)?)
        }
        "duplicate_of_uri" => {
            let p: UriParams = take(params)?;
            value(vault.duplicate_of_uri(p.uri)?)
        }
        "add_manual" => {
            let p: AddManualParams = take(params)?;
            value(vault.add_manual(p.draft, p.now_ms)?)
        }
        "set_note" => {
            let p: SetNoteParams = take(params)?;
            value(vault.set_note(p.id, p.note, p.now_ms)?)
        }
        "rename" => {
            let p: RenameParams = take(params)?;
            value(vault.rename(p.id, p.issuer, p.account, p.now_ms)?)
        }
        "delete" => {
            let p: IdAtParams = take(params)?;
            value(vault.delete(p.id, p.now_ms)?)
        }
        "reorder" => {
            let p: ReorderParams = take(params)?;
            value(vault.reorder(p.ids, p.now_ms)?)
        }
        "prune_tombstones" => {
            let p: NowMsParams = take(params)?;
            value(vault.prune_tombstones(p.now_ms))
        }
        "import_migration" => {
            let p: ImportMigrationParams = take(params)?;
            value(vault.import_migration(p.uris, p.now_ms)?)
        }
        "export_backup" => {
            let p: PasswordParams = take(params)?;
            value(Base64Bytes(vault.export_backup(p.password)?))
        }
        "import_backup" => {
            let p: ImportBackupParams = take(params)?;
            value(vault.import_backup(p.file, p.password)?)
        }
        "lock_config" => value(vault.lock_config()),
        "set_lock_config" => {
            let p: SetLockParams = take(params)?;
            vault.set_lock_config(p.config, p.now_ms);
            value(())
        }
        "set_pin" => {
            let p: SetPinParams = take(params)?;
            value(vault.set_pin(p.pin, p.now_ms)?)
        }
        "clear_pin" => {
            let p: NowMsParams = take(params)?;
            vault.clear_pin(p.now_ms);
            value(())
        }
        "verify_pin" => {
            let p: PinParams = take(params)?;
            value(vault.verify_pin(p.pin))
        }
        "preferences" => value(vault.preferences()),
        "set_preferences" => {
            let p: SetPreferencesParams = take(params)?;
            vault.set_preferences(p.preferences, p.now_ms);
            value(())
        }
        "sync_targets" => value(vault.sync_targets()),
        "upsert_sync_target" => {
            let p: UpsertTargetParams = take(params)?;
            value(vault.upsert_sync_target(p.target, p.now_ms)?)
        }
        "remove_sync_target" => {
            let p: IdAtParams = take(params)?;
            value(vault.remove_sync_target(p.id, p.now_ms)?)
        }
        "sync" => {
            let p: SyncParams = take(params)?;
            value(vault.sync(p.remotes, p.sync_key)?)
        }
        unknown => Err(MfaError::of(
            ErrorKind::Other,
            format!("unknown method `{unknown}`"),
        )),
    }
}

impl Registry {
    fn insert(&mut self, vault: VaultHandle) -> u64 {
        self.next += 1;
        self.open.insert(self.next, Arc::new(vault));
        self.next
    }

    /// Looks a handle up. A closed or never-issued handle is an error rather
    /// than a crash.
    fn get(&self, handle: u64) -> crate::error::Result<Arc<VaultHandle>> {
        self.open.get(&handle).cloned().ok_or_else(|| {
            MfaError::of(
                ErrorKind::NotFound,
                format!("handle {handle} is not open; call `open` or `create` first"),
            )
        })
    }
}

fn missing_handle() -> MfaError {
    MfaError::of(ErrorKind::Other, "this method needs a `handle`")
}

fn take<T: serde::de::DeserializeOwned>(params: Value) -> crate::error::Result<T> {
    serde_json::from_value(params)
        .map_err(|error| MfaError::of(ErrorKind::Other, format!("bad parameters: {error}")))
}

fn value<T: Serialize>(result: T) -> crate::error::Result<Value> {
    serde_json::to_value(result)
        .map_err(|error| MfaError::of(ErrorKind::Other, format!("bad result: {error}")))
}

// The parameter shapes, one per method that takes any. Named after what they
// carry rather than after the method, so the obvious ones are shared.

#[derive(Deserialize)]
struct CreateParams {
    #[serde(with = "crate::jsonbytes::required")]
    data_key: Vec<u8>,
}
#[derive(Deserialize)]
struct OpenParams {
    #[serde(with = "crate::jsonbytes::required")]
    data_key: Vec<u8>,
    #[serde(with = "crate::jsonbytes::required")]
    file: Vec<u8>,
}
#[derive(Deserialize)]
struct WrapKeyParams {
    #[serde(with = "crate::jsonbytes::required")]
    sync_key: Vec<u8>,
    password: String,
}
#[derive(Deserialize)]
struct UnwrapKeyParams {
    #[serde(with = "crate::jsonbytes::required")]
    key_file: Vec<u8>,
    password: String,
}
#[derive(Deserialize)]
struct UriParams {
    uri: String,
}
#[derive(Deserialize)]
struct UrisParams {
    uris: Vec<String>,
}
#[derive(Deserialize)]
struct FileParams {
    #[serde(with = "crate::jsonbytes::required")]
    file: Vec<u8>,
}
#[cfg(feature = "qr-image")]
#[derive(Deserialize)]
struct ImageParams {
    #[serde(with = "crate::jsonbytes::required")]
    image: Vec<u8>,
}
#[derive(Deserialize)]
struct NowSecsParams {
    now_secs: u64,
}
#[derive(Deserialize)]
struct NowMsParams {
    now_ms: i64,
}
#[derive(Deserialize)]
struct SearchParams {
    query: String,
    now_secs: u64,
}
#[derive(Deserialize)]
struct CodeParams {
    id: String,
    now_secs: u64,
}
#[derive(Deserialize)]
struct IdParams {
    id: String,
}
#[derive(Deserialize)]
struct IdAtParams {
    id: String,
    now_ms: i64,
}
#[derive(Deserialize)]
struct AddUriParams {
    uri: String,
    now_ms: i64,
}
#[derive(Deserialize)]
struct AddManualParams {
    draft: AccountDraft,
    now_ms: i64,
}
#[derive(Deserialize)]
struct SetNoteParams {
    id: String,
    #[serde(default)]
    note: Option<String>,
    now_ms: i64,
}
#[derive(Deserialize)]
struct RenameParams {
    id: String,
    #[serde(default)]
    issuer: Option<String>,
    account: String,
    now_ms: i64,
}
#[derive(Deserialize)]
struct ReorderParams {
    ids: Vec<String>,
    now_ms: i64,
}
#[derive(Deserialize)]
struct ImportMigrationParams {
    uris: Vec<String>,
    now_ms: i64,
}
#[derive(Deserialize)]
struct PasswordParams {
    password: String,
}
#[derive(Deserialize)]
struct ImportBackupParams {
    #[serde(with = "crate::jsonbytes::required")]
    file: Vec<u8>,
    password: String,
}
#[derive(Deserialize)]
struct SetLockParams {
    config: LockConfig,
    now_ms: i64,
}
#[derive(Deserialize)]
struct SetPinParams {
    pin: String,
    now_ms: i64,
}
#[derive(Deserialize)]
struct PinParams {
    pin: String,
}
#[derive(Deserialize)]
struct SetPreferencesParams {
    preferences: Preferences,
    now_ms: i64,
}
#[derive(Deserialize)]
struct UpsertTargetParams {
    target: SyncTargetView,
    now_ms: i64,
}
#[derive(Deserialize)]
struct SyncParams {
    remotes: Vec<RemoteFile>,
    #[serde(with = "crate::jsonbytes::required")]
    sync_key: Vec<u8>,
}
