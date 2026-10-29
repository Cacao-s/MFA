"""Independent minimal protobuf encoder for Google Authenticator migration
payloads. Written from the published MigrationPayload schema, on purpose with
no shared code with the Rust decoder it is used to test."""
import base64, urllib.parse

def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)

def tag(field, wire):   return varint((field << 3) | wire)
def ld(field, payload): return tag(field, 2) + varint(len(payload)) + payload
def vi(field, value):   return tag(field, 0) + varint(value)

def otp(secret, name, issuer, algo, digits, otype, counter=None):
    m = ld(1, secret) + ld(2, name.encode()) + ld(3, issuer.encode())
    m += vi(4, algo) + vi(5, digits) + vi(6, otype)
    if counter is not None:
        m += vi(7, counter)
    return m

def payload(entries, version=1, batch_size=1, batch_index=0, batch_id=0):
    body = b"".join(ld(1, e) for e in entries)
    return body + vi(2, version) + vi(3, batch_size) + vi(4, batch_index) + vi(5, batch_id)

ALGO = {"SHA1": 1, "SHA256": 2, "SHA512": 3, "MD5": 4}
DIG  = {6: 1, 8: 2}
TOTP, HOTP = 2, 1

hello   = b"Hello!\xde\xad\xbe\xef"
rfcseed = b"12345678901234567890"

# --- single-code export: two importable TOTP accounts + one HOTP to skip ---
single = payload([
    otp(hello,   "alice@example.com", "Example",  ALGO["SHA1"],   DIG[6], TOTP),
    otp(rfcseed, "bob",               "Big Corp", ALGO["SHA256"], DIG[8], TOTP),
    otp(hello,   "legacy",            "Old Bank", ALGO["SHA1"],   DIG[6], HOTP, counter=5),
], batch_size=1, batch_index=0, batch_id=1234567)

# --- two-code export, same batch_id ---
b0 = payload([otp(hello,   "first@example.com",  "One", ALGO["SHA1"],   DIG[6], TOTP)],
             batch_size=2, batch_index=0, batch_id=424242)
b1 = payload([otp(rfcseed, "second@example.com", "Two", ALGO["SHA512"], DIG[8], TOTP)],
             batch_size=2, batch_index=1, batch_id=424242)

# --- an MD5 entry, which we refuse to generate codes for ---
md5 = payload([otp(hello, "md5@example.com", "Weird", ALGO["MD5"], DIG[6], TOTP)],
              batch_size=1, batch_index=0, batch_id=9)

def uri(p, quote=True):
    data = base64.b64encode(p).decode()
    return "otpauth-migration://offline?data=" + (urllib.parse.quote(data, safe="") if quote else data)

import base64 as b64
def b32(x):
    return b64.b32encode(x).decode().rstrip("=")

for name, p in [("SINGLE", single), ("BATCH_0", b0), ("BATCH_1", b1), ("MD5_ONLY", md5)]:
    print(f'pub const {name}: &str = "{uri(p)}";')
print()
print("// raw (unquoted) form, to prove we accept both:")
print(f'pub const SINGLE_UNQUOTED: &str = "{uri(single, quote=False)}";')
print()
print("// base32 of the fixture secrets")
print("hello  ->", b32(hello))
print("rfcseed->", b32(rfcseed))
