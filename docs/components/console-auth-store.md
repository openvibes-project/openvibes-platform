# Console authentication store

`platform_store::console_auth` persists local console credentials, pre-auth
state, sessions, and login throttles. It stores only credential PHC strings
and SHA-256 digests of opaque browser values; plaintext passwords, session
tokens, and CSRF values stay in the console process.

## Interface

- `create_local_user` inserts a local user, Argon2id PHC credential, global
  role binding, and audit event in one transaction.
- `credential_by_username` returns the PHC string and account generation,
  including disabled accounts so the caller can keep password-failure work
  indistinguishable.
- `user_role_bindings` returns active bindings for per-request capability
  resolution. It does not cache effective permission state.
- `create_session` accepts only a currently enabled account at the generation
  observed after password verification. Session lookups require matching
  account generation, no revocation, and both idle and absolute expiry in the
  future. `touch_session` never extends absolute expiry; `revoke_user_sessions`
  advances the account generation, revokes its sessions, and writes one audit
  event atomically.
- `replace_password` replaces the PHC credential, advances auth generation,
  revokes all sessions, and appends its audit event in one transaction.
  `disable_local_user` disables an account and revokes its sessions with the
  same atomic audit guarantee.
- `create_preauth` / `consume_preauth` store and consume state only when the
  token, CSRF, and browser-binding digests all match and the state is live.
- `login_is_throttled`, `record_login_failure`, and `clear_login_throttle`
  operate on caller-derived account and source bucket digests. Window, failure
  count, and lock duration are policy inputs supplied by the console.
  `record_login_failure` updates both buckets and writes a redacted generic
  failure event in the same transaction. Session creation writes a successful
  login event; user creation writes its provisioning event.

## Configuration and failures

The store has no independent configuration. It uses the console's existing
PostgreSQL pool and bounded statement timeout. Database errors map to the
platform's fixed `StoreError` categories; no SQL, credentials, tokens, or
connection strings are returned to the caller. The login handler must still
perform fixed-cost dummy Argon2id verification for unknown users and enforce
Origin/CSRF checks. It must pass only trusted request metadata into audit
context fields and never include credentials or browser secrets.

## How to test

```sh
eval "$(scripts/test-db.sh)"
cargo test --locked -p platform-store --test console_auth
```

Tests create and drop independent PostgreSQL databases. They fail rather than
skip when `OPENVIBES_TEST_DATABASE_URL` is missing.
