# Console authentication primitives

`crates/openvibes-console/src/auth.rs` contains the console's opaque browser
session-secret primitive. It creates a 256-bit random value, exposes it for
the cookie, and derives a SHA-256 digest for database storage. Its `Debug`
output redacts both values. The cookie helper emits the approved `__Host-`
cookie with `Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/` attributes.
It also checks an exact, single `Origin` header against the canonical
configured origin and rejects `Sec-Fetch-Site: cross-site` when supplied.
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

This module does not authenticate users or manage sessions. Those operations
remain unavailable until C3's database schema and store boundary are integrated.
The origin checker receives a canonical origin from validated runtime config;
it does not interpret forwarded headers. The agreed common-password blocklist
and production login throttling are not implemented here yet. Callers must
run the synchronous Argon2 operation under bounded blocking capacity. Random
source failure returns an error so callers can fail closed.

Run `cargo test -p openvibes-console auth::tests`.
