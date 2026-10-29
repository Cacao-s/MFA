"""Independent TOTP reference using the Python standard library."""
import hmac, hashlib, struct

def totp(key, t, digits=6, period=30, hashfn=hashlib.sha1):
    d = hmac.new(key, struct.pack(">Q", t // period), hashfn).digest()
    o = d[-1] & 0x0F
    code = struct.unpack(">I", d[o:o+4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)

key20 = b"12345678901234567890"
key32 = b"12345678901234567890123456789012"
hello = b"Hello!\xde\xad\xbe\xef"

print("20-byte seed, SHA256, 8 digits, T=59 :", totp(key20, 59, 8, 30, hashlib.sha256))
print("RFC check  32-byte seed SHA256 T=59  :", totp(key32, 59, 8, 30, hashlib.sha256))
print("hello seed, SHA1, 6 digits, T=59     :", totp(hello, 59, 6, 30, hashlib.sha1))
print("hello seed, SHA1, 6 digits, T=1e9    :", totp(hello, 1000000000, 6, 30, hashlib.sha1))
