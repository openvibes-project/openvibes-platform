# Console authentication primitives

`crates/openvibes-console/src/auth.rs` contains the console's opaque browser
session-secret primitive. It creates a 256-bit random value, exposes it for
the cookie, and derives a SHA-256 digest for database storage. Its `Debug`
output redacts both values. The cookie helper emits the approved `__Host-`
cookie with `Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/` attributes.

This module does not authenticate users or manage sessions. Those operations
remain unavailable until C3's database schema and store boundary are integrated.
It has no configuration. Random-source failure returns an error so callers
can fail closed.

Run `cargo test -p openvibes-console auth::tests::session_cookie_is_opaque_and_only_the_digest_is_persistable`.
