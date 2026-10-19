# Console authentication store

`platform_store::console_auth` persists local console credentials, pre-auth
state, sessions, and login throttles. It stores only credential PHC strings
and SHA-256 digests of opaque browser values; plaintext passwords, session
tokens, and CSRF values stay in the console process.

## Interface

- `create_local_user` inserts a local user, Argon2id PHC credential, role
  binding, and audit event in one transaction.
- `credential_by_username` returns the PHC string and account generation,
  including disabled accounts so the caller can keep password-failure work
  indistinguishable.
- `list_local_users` exposes only non-secret account metadata, active roles,
  and last session activity for the audited local administration CLI.
- `unlock_local_user` clears only a currently locked account throttle bucket
  and writes the unlock event atomically. Source-address throttles remain in
  effect.
- `user_role_bindings` returns active bindings (role ids; since schema 52 a
  binding has no group scope, the role carries its reach) for per-request
  capability resolution. It does not cache effective permission state.
- `console_people` (People, spec §9.1): `people`/`person` (email,
  `auth_source`, `last_sign_in_at`, active role ids), `recent_activity` (the
  newest audit rows with the person as `actor_id`, served by
  `audit_log_actor_recent_idx`), `create_user` (several roles and an email
  in one transaction with `create_local_user`'s writes), `set_details`
  (`user.updated`), `enable_user` (`user.enabled`), `reset_password` (new
  one-time hash, `password_must_change`, generation bump and every session
  revoked, `user.password_reset`, one transaction).
- `create_enrollment_token` stores only the SHA-256 digest of the decoded
  32-byte secret. It serializes each actor/idempotency-key pair and atomically
  stores token metadata, a 24-hour request/response idempotency record, and
  the audit event. A matching retry returns metadata only; a different request
  under the same key conflicts. `list_enrollment_tokens` returns bounded
  secret-free metadata; `revoke_enrollment_token` commits its audit row with
  the revocation.
- Service-account operations create identities holding one or more roles,
  issue and list expiring hash-only bearer tokens, revoke individual tokens,
  and atomically disable an identity with all of its tokens. Issuance is
  idempotent for 24 hours and never stores the token secret in its replay row.
  Active bearer
  authentication checks token expiry/revocation and account enabled state on
  each request, then resolves the account's current role bindings.
- Rule-bundle publication uses the shared rule store to recheck set lifecycle,
  monotonic version, exact-byte replay, and active issuer trust under the set
  advisory lock. Console publication writes the bundle and a redacted audit
  row in the same transaction. Migration 10 grants the console role `SELECT`
  on public trust keys only; trust-key changes remain local CLI operations.
- Tags, tag selectors and their writes (`save_asset_group`,
  `preview_agent_tags`, `apply_agent_tags`) are gone since schema 53: host
  groups and labels replace them (platform-store.md "Host groups"). The
  console's old tag and asset-group routes are gone (404).
- `revoke_agent_in_scope` checks the caller's scope with
  `console_read::agent_visibility`, so a scoped caller can revoke only an
  active host in one of its groups.
- `console_people::give_role` and `remove_role` give or take a role from a
  user or service account (`Principal`) with `rbac.binding.created` /
  `rbac.binding.revoked` in the same transaction, under the access-binding
  advisory lock. Giving a held role changes nothing (`AlreadyHeld`); removal
  refuses (`LastAdministrator`) to take `admin` from the last enabled
  Administrator, counted by `enabled_administrators`, so two concurrent
  removals cannot both succeed.
- Host groups and labels have their own store modules (`host_groups`,
  `host_group_writes`, `host_labels`; platform-store.md "Host-group store
  API"); the console's host-group routes are in `src/hosts/groups.rs`.
  `host_groups::picked_ids` returns only active members, so a manual group
  updated through it drops its non-active members.
- `create_session` stamps `console_users.last_sign_in_at` and accepts only a currently enabled account at the generation
  observed after password verification and can revoke the prior session in the
  same transaction during login rotation. Session lookups require matching
  account generation, no revocation, and both idle and absolute expiry in the
  future. `touch_session` never extends absolute expiry; `revoke_user_sessions`
  advances the account generation, revokes its sessions, and writes one audit
  event atomically. `revoke_session` revokes only one session and writes the
  logout event in the same transaction.
- `replace_password` replaces the PHC credential, advances auth generation,
  revokes all sessions, and appends its audit event in one transaction.
  `rehash_password` upgrades an existing hash only at the generation just
  verified and records the upgrade without invalidating the new login.
  `disable_local_user` disables an account and revokes its sessions with the
  same atomic audit guarantee; it takes the access-binding lock and returns
  `DisableOutcome::{Disabled, NotFound, LastAdministrator}`, never disabling
  the last enabled Administrator.
- `create_preauth` / `consume_preauth` store and consume state only when the
  token, CSRF, and browser-binding digests all match and the state is live.
- `login_is_throttled`, `record_login_failure`, and `clear_login_throttle`
  operate on caller-derived account and source bucket digests. Window, failure
  count, and lock duration are policy inputs supplied by the console.
  `record_login_failure` updates both buckets and writes a redacted generic
  failure event in the same transaction. Session creation writes a successful
  login event; user creation writes its provisioning event.

## Roles (`console_roles`, schema 52)

`platform_store::console_roles` stores roles as named permission sets with a
host reach (spec 2026-10-16-roles-permissions-design.md §4): `Reach::None`,
`All` (`console_roles.all_hosts`) or `Groups` (`console_role_groups`).

- `list_roles` / `role` return `StoredRole` (permissions, reach, reached
  group names, active member count, version).
- `create_role`, `update_role` (optimistic `version`) and `delete_role` run in
  one transaction under the access-binding advisory lock, write an
  `rbac.role.created/updated/deleted` audit row (target kind `role`, detail
  name, permissions, reach), and return `RoleWrite`: `Saved`, `NameTaken`
  (unique `lower(display_name)`), `UnknownReference` (a permission or group
  id that does not exist, or a group deleted during the write; duplicate ids
  collapse), `Stale`, `NotFound`, `Protected` (`admin`,
  shown as Administrator, is never changed or deleted) or `InUse(n)` (a role
  with active bindings is not deleted; dashboards shared with a deleted role
  lose that share). The audit row carries the caller's `now`. New ids are `r_` and 16 hex digits.
  The store does not check permission closure or the editor's share; the
  console does.
- `grants(client, Principal::User | ServiceAccount)` returns, in one query,
  each held role's permissions and reach.

Migration 52 converts existing data (§12 parts 2–3): Administrator keeps id
`admin`; viewer, analyst and operator become ordinary roles reaching all
hosts when held and are deleted otherwise (so a fresh install has only
Administrator); each holder's scoped bindings of one role become one role
"<Role> (<groups>)" with the old agent-scoped permissions only, and an
`rbac.binding.migrated` audit row per moved binding. Dashboard shares move to
`console_dashboard_roles` and follow scoped holders to their new roles. Revoked bindings of a
deleted role go with it. `console_users` gains `email`, `auth_source` and
`last_sign_in_at`.

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
cargo test --locked -p platform-store --test console_auth --test custom_roles --test role_writes
```

Tests create and drop independent PostgreSQL databases. They fail rather than
skip when `OPENVIBES_TEST_DATABASE_URL` is missing.
