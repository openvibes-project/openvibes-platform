# Console authentication primitives

`crates/openvibes-console/src/auth.rs` contains the console's opaque browser
session-secret primitive. It creates a 256-bit random value, exposes it for
the cookie, and derives a SHA-256 digest for database storage. Its `Debug`
output redacts both values. The cookie helper emits the approved `__Host-`
cookie with `Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/` attributes.
It also checks an exact, single `Origin` header against the canonical
configured origin and rejects `Sec-Fetch-Site: cross-site` when supplied.
`csrf_token_matches` requires exactly one `X-CSRF-Token` value and compares
equal-length tokens with `subtle::ConstantTimeEq`; the caller supplies the
current session's expected token. `presented_credentials` accepts either one
valid session cookie or one bearer credential, rejects duplicates and mixed
credentials, and redacts/zeroizes parsed token strings.
`SessionLifetime` enforces a 30-minute idle deadline and an eight-hour
absolute deadline; activity refreshes only the idle deadline. Restoring a
session rejects impossible timestamp ordering; checking it against current time
fails closed for future activity, overflow, or expired deadlines.
`NormalizedPassword` converts input to NFC, enforces 15–128 Unicode code
points without trimming or truncating, redacts `Debug`, and clears its owned
buffer on drop. Inputs above 4,096 raw code points are rejected before
normalization to bound work.
`hash_password` produces a per-password-salted Argon2id v19 PHC credential at
the OWASP minimum of 19 MiB, two iterations, and one lane. Verification rejects
non-Argon2id, unsupported versions, overlong PHC strings, and parameters above
64 MiB, five iterations, or four lanes before running the KDF. Successful
verification reports when the stored parameters are below the current floor.
The RustCrypto implementation's memory-wiping feature is enabled.
The password constructor rejects a small bounded list of exact common
passphrases after normalization. This list is only an initial seed and must be
replaced or expanded from a reviewed local compromised-password corpus before
production login is enabled.

The C3 HTTP adapter and database operations are documented in
[`console-auth-http.md`](console-auth-http.md) and
[`console-auth-store.md`](console-auth-store.md). The origin checker receives a
canonical origin from validated runtime config; it does not interpret forwarded
headers. The blocklist is not a comprehensive compromised-password corpus.
Callers must run the synchronous Argon2 operation under bounded blocking
capacity. Random-source failure returns an error so callers can fail closed.

Run `cargo test -p openvibes-console auth::tests`.
