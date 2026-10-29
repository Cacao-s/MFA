/*
 * The JSON command bus (crates/mfa-ffi/src/capi.rs).
 *
 * For Windows and anything else without a first-party UniFFI generator. Swift
 * and Kotlin should use the generated bindings instead: `make bindings`.
 *
 * Two functions, both UTF-8 JSON:
 *
 *     char *response = mfa_call("{\"method\":\"library_version\"}");
 *     // ... read it ...
 *     mfa_string_free(response);
 *
 * A response is {"ok": <result>} or
 * {"error": {"kind": "...", "message": "..."}}. The method names and
 * parameters are documented in src/capi.rs.
 */

#ifndef MFA_FFI_H
#define MFA_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Handles one request. Never returns NULL. The caller owns the result and
 * must release it with mfa_string_free.
 *
 * request_json may be NULL, which comes back as an error response.
 */
char *mfa_call(const char *request_json);

/*
 * Releases a string returned by mfa_call. Passing NULL is a no-op. Passing
 * anything else, or the same pointer twice, is undefined behaviour.
 */
void mfa_string_free(char *response_json);

#ifdef __cplusplus
}
#endif

#endif /* MFA_FFI_H */
