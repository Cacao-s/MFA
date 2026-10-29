//! The JSON command bus, including the pointer path a C caller takes.

use std::ffi::{CStr, CString};

use mfa_ffi::capi::{dispatch_text, mfa_call, mfa_string_free};
use serde_json::{json, Value};

const T0: i64 = 1_700_000_000_000;
const URI: &str = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";

/// Sends a request and returns the parsed response.
fn call(request: Value) -> Value {
    serde_json::from_str(&dispatch_text(&request.to_string())).expect("a JSON response")
}

/// Sends a request and unwraps `ok`, panicking on an error response.
fn ok(request: Value) -> Value {
    let response = call(request);
    response
        .get("ok")
        .cloned()
        .unwrap_or_else(|| panic!("expected ok, got {response}"))
}

/// Sends a request and returns the error's `kind`.
fn error_kind(request: Value) -> String {
    let response = call(request);
    response["error"]["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("expected an error, got {response}"))
        .to_owned()
}

/// A fresh vault, returning its handle and data key.
fn open_vault() -> (u64, Value) {
    let key = ok(json!({"method": "generate_data_key"}));
    let opened = ok(json!({"method": "create", "params": {"data_key": key}}));
    (opened["handle"].as_u64().expect("a handle"), key)
}

#[test]
fn a_whole_session_goes_through_json() {
    let (handle, key) = open_vault();

    let id = ok(json!({
        "method": "add_uri", "handle": handle,
        "params": {"uri": URI, "now_ms": T0}
    }));

    let accounts = ok(json!({
        "method": "accounts", "handle": handle,
        "params": {"now_secs": 59}
    }));
    assert_eq!(accounts.as_array().unwrap().len(), 1);
    assert_eq!(accounts[0]["id"], id);
    assert_eq!(accounts[0]["display_name"], "Example (alice@example.com)");
    // Cross-checked against Python's hmac (tools/totp_ref.py).
    assert_eq!(accounts[0]["code"], "996554");
    assert_eq!(accounts[0]["remaining_secs"], 1);

    // Seal, reopen, and the account is still there.
    let file = ok(json!({"method": "seal", "handle": handle}));
    let reopened = ok(json!({"method": "open", "params": {"data_key": key, "file": file}}));
    let second = reopened["handle"].as_u64().unwrap();

    let again = ok(json!({
        "method": "accounts", "handle": second,
        "params": {"now_secs": 59}
    }));
    assert_eq!(again, accounts);
}

#[test]
fn a_handle_can_be_closed_and_is_then_refused() {
    let (handle, _) = open_vault();
    assert_eq!(ok(json!({"method": "count", "handle": handle})), 0);

    assert_eq!(ok(json!({"method": "close", "handle": handle})), true);
    // Closing twice says so rather than failing.
    assert_eq!(ok(json!({"method": "close", "handle": handle})), false);

    // And the handle is no longer usable, with a message that says what to do.
    let response = call(json!({"method": "count", "handle": handle}));
    assert_eq!(response["error"]["kind"], "NotFound");
    assert!(response["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not open"));
}

#[test]
fn a_bad_request_is_an_error_rather_than_a_crash() {
    // Not JSON at all.
    let response: Value = serde_json::from_str(&dispatch_text("}{")).unwrap();
    assert!(response.get("error").is_some());

    // No such method.
    assert_eq!(error_kind(json!({"method": "fly"})), "Other");

    // A method that needs a handle, without one.
    assert_eq!(error_kind(json!({"method": "count"})), "Other");

    // Right method, wrong parameters.
    let (handle, _) = open_vault();
    assert_eq!(
        error_kind(json!({"method": "accounts", "handle": handle, "params": {}})),
        "Other"
    );
    assert_eq!(
        error_kind(json!({
            "method": "accounts", "handle": handle,
            "params": {"now_secs": "half past three"}
        })),
        "Other"
    );

    // A handle that was never issued.
    assert_eq!(
        error_kind(json!({"method": "count", "handle": 999_999})),
        "NotFound"
    );
}

#[test]
fn failures_carry_a_kind_the_caller_can_branch_on() {
    let (handle, _) = open_vault();
    ok(json!({"method": "add_uri", "handle": handle, "params": {"uri": URI, "now_ms": T0}}));

    let backup = ok(json!({
        "method": "export_backup", "handle": handle,
        "params": {"password": "correct horse battery"}
    }));

    assert_eq!(
        error_kind(json!({
            "method": "import_backup", "handle": handle,
            "params": {"file": backup, "password": "wrong"}
        })),
        "WrongPassword"
    );
    assert_eq!(
        error_kind(json!({"method": "preview_uri", "params": {"uri": "https://example.com"}})),
        "BadUri"
    );
    assert_eq!(
        error_kind(json!({
            "method": "open",
            "params": {"data_key": vec![0u8; 32], "file": vec![0u8; 64]}
        })),
        "BadFile"
    );
}

#[test]
fn the_settings_and_sync_surface_is_reachable() {
    let (handle, _) = open_vault();

    assert_eq!(
        ok(json!({"method": "lock_config", "handle": handle}))["background_timeout_secs"],
        30
    );
    ok(json!({
        "method": "set_pin", "handle": handle,
        "params": {"pin": "1379", "now_ms": T0}
    }));
    assert_eq!(
        ok(json!({"method": "verify_pin", "handle": handle, "params": {"pin": "1379"}})),
        true
    );
    assert_eq!(
        ok(json!({"method": "verify_pin", "handle": handle, "params": {"pin": "0000"}})),
        false
    );

    let target_id = ok(json!({
        "method": "upsert_sync_target", "handle": handle,
        "params": {"target": {
            "id": "", "kind": "Server", "label": "home",
            "location": "https://mfa.example.com", "enabled": true
        }, "now_ms": T0}
    }));
    let targets = ok(json!({"method": "sync_targets", "handle": handle}));
    assert_eq!(targets.as_array().unwrap().len(), 1);
    assert_eq!(targets[0]["id"], target_id);
    assert_eq!(targets[0]["kind"], "Server");

    // One sync round, with the target still empty.
    let sync_key = ok(json!({"method": "new_sync_key"}));
    let round = ok(json!({
        "method": "sync", "handle": handle,
        "params": {
            "remotes": [{"target": target_id, "bytes": null}],
            "sync_key": sync_key
        }
    }));
    assert_eq!(round["uploads"].as_array().unwrap().len(), 1);
    assert_eq!(round["uploads"][0]["target"], target_id);
    assert!(round["failures"].as_array().unwrap().is_empty());
}

#[test]
fn the_c_entry_point_works_through_pointers() {
    // What a C# `DllImport` actually does.
    let request = CString::new(r#"{"method":"library_version"}"#).unwrap();

    let response = unsafe { mfa_call(request.as_ptr()) };
    assert!(!response.is_null());

    let text = unsafe { CStr::from_ptr(response) }
        .to_str()
        .expect("UTF-8")
        .to_owned();
    unsafe { mfa_string_free(response) };

    let parsed: Value = serde_json::from_str(&text).unwrap();
    assert!(parsed["ok"]
        .as_str()
        .is_some_and(|version| !version.is_empty()));

    // A null request is answered, not crashed on.
    let response = unsafe { mfa_call(core::ptr::null()) };
    let text = unsafe { CStr::from_ptr(response) }
        .to_str()
        .unwrap()
        .to_owned();
    unsafe { mfa_string_free(response) };
    assert!(serde_json::from_str::<Value>(&text).unwrap()["error"].is_object());

    // Freeing null is a no-op rather than a crash.
    unsafe { mfa_string_free(core::ptr::null_mut()) };
}
