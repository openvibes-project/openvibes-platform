# Console authentication HTTP adapter

The C3 HTTP adapter validates a browser session against `platform_store::console_auth`
and builds the stable `GET /api/v1/session` response. It also exposes
permission-checked read models, enrollment-token management, and audit routes.

## Interface

- `authenticated_router(pool, public_origin)` builds a router with database-
  backed authentication. `public_origin` is the canonical configured browser
  origin; `public_router()` remains the C0 fail-closed router.
  `authenticated_router_for_hosts(pool, public_origin, hosts)` also serves
  `hosts` (`name:port`); the executable passes the server certificate's
  names in direct-TLS mode (board #71).
- `GET /api/v1/session` accepts exactly one valid `__Host-openvibes-session`
  cookie, rejects bearer or conflicting credentials, checks session and CSRF
  digests in constant time, touches the bounded idle expiry, and resolves active
  role bindings on each request. Its `capabilities` leave out `assistant.use`
  while no assistant is set up (the web hides the assistant by it); permission
  and share checks read the unfiltered set.
- `GET /auth/v1/preauth` stores a five-minute, one-use hash-only challenge and
  returns its CSRF token with separate HttpOnly pre-auth and browser-binding
  cookies. It sets no cookies if persistence fails. The in-memory secret
  wrappers clear their owned buffers when dropped.
- `POST /auth/v1/login` requires that pre-auth challenge, matching CSRF header,
  exact Origin, and a socket peer address supplied through `ConnectInfo`.
  Account and source throttles are hashed and domain-separated. Password
  verification runs in a blocking worker behind a four-slot bound, with a
  cached dummy Argon2id credential for missing, disabled, invalid, and locked
  accounts. Failures use a generic response and are audited; success creates a
  fresh opaque session and clears the one-use pre-auth cookies. Older valid
  Argon2 hashes are upgraded without changing the auth generation.
- `POST /auth/v1/logout` enforces the same Origin and synchronizer-token checks,
  revokes only the presented session, records the logout in the audit log, and
  clears the session cookie. Repeating logout remains safe.
- `GET /api/v1/enrollment-tokens` returns at most 100 newest token metadata
  rows and never returns token hashes or plaintext. `POST` requires
  `tokens.manage`, CSRF, and an `Idempotency-Key`; successful creation returns
  the secret once, while a same-key/same-request retry returns metadata with
  `secret_available=false`. Reusing a key for different settings returns 409.
  `GET /api/v1/enrollment-tokens/{token_id}` returns one secret-free record.
  `POST /api/v1/enrollment-tokens/{token_id}/revoke` requires `tokens.manage`
  and audits the revocation. These responses are `Cache-Control: no-store`.
- `/api/v1/service-accounts` lists safe account metadata (filtered to the
  caller's share for non-administrators), each account's roles as
  `roles: [{role_id, name}]`, and creates an account holding `role_ids`
  (1–64, each inside the creator's share; an unknown role id is
  400 `unknown_role`, as for `POST /api/v1/users`). Creating an account or
  issuing a token checks the session, CSRF and permission (and the account's
  share) before reading the body: a caller who may not gets 401 or 403
  whatever they send.
  `PUT`/`DELETE /api/v1/service-accounts/{id}/roles/{role}` give or take a
  role (`access.grant` and the share). The token list, issue and revoke
  routes and disable also need the account inside the caller's share
  (`people_roles::account_in_share`); an account outside it answers 404
  `service_account_not_found`, like one that does not exist, so nobody
  mints a token for an account holding more than they do. Per-account token routes list metadata, issue
  an expiring `ovc_` bearer secret once, revoke a token, or disable the account
  (which also revokes all its tokens). Token issue requires an
  `Idempotency-Key`; a matching retry returns metadata without the original
  secret and a mismatched retry returns 409. These mutations require
  `service_accounts.manage`; reads require `service_accounts.read`.
  Service-account bearer credentials are accepted for scoped read routes, and
  are rejected when mixed with a browser cookie. The first-release adapter
  refuses bearer-authenticated mutations; those require a browser session and
  CSRF checks.
- `/api/v1/rule-sets` and per-set bundle history are global `rules.read`
  reads; the operator and admin roles hold it (since schema 51). Rule upload preview verifies the
  Ed25519 signature, envelope digest,
  expiry, parser limits, and currently trusted issuer against read-only public
  trust keys. Publish repeats verification, binds the confirmation token to
  the exact bytes, and stores the bundle plus its audit row atomically. The
  console never manages private signing keys or trust-key changes.
- `/api/v1/rule-set-assignments` (the per-group switches of the assignable
  sets) reads with global `rules.assignment.read` and changes with
  `rules.assignment.write` plus CSRF; see [rule-set-assignment.md](rule-set-assignment.md).
- Missing, malformed, expired, revoked, disabled, or stale-generation sessions
  receive the same generic `401` problem. Store failures return a generic `503`.
- Session responses are `Cache-Control: no-store`. The CSRF token is derived
  from the high-entropy session secret with a domain separator; only its digest
  is persisted by the store.

### Authentication first (#97)

Every authenticated `/api` route except `GET /api/v1/session` and `POST
/api/v1/session/password` passes `auth_first::authenticate_first` before
its handler, and so before axum parses the body: no session or token is
401, and a user who must still set their own password is 403
`password_change_required`. Nothing about a request (a malformed body, a
field rule, whether the assistant is on) reaches an unauthenticated
caller. Handlers still check their own permission, scope and CSRF.
`tests/auth_first_http.rs` sends a malformed body to every `/api` route
in the OpenAPI document, with no session and with a forced-change one.

### People (spec §9.1, §13)

| Route | Needs | Answer |
|---|---|---|
| `GET /api/v1/users` | `access.read` | `[PersonRow]`, only people inside the share for non-administrators |
| `GET /api/v1/users/{id}` | `access.read` and the share, or one's own | `PersonView`: details, roles, access lines (`applies` all, groups or platform, `from_role`), the newest 10 actions |
| `POST /api/v1/users` | `access.users`, roles inside the share | 201 `CreatedUser` with a one-time password |
| `PATCH /api/v1/users/{id}` | one's own, or `access.users` and the share | 204; 422 `invalid_email`/`invalid_user`; `user.updated` |
| `POST /api/v1/users/{id}/disable`, `/enable` | `access.users` and the share; never oneself | 204; 409 `last_administrator` |
| `POST /api/v1/users/{id}/reset-password` | `access.users` and the share; never oneself (403 `use_change_password`) | `{one_time_password}` (`no-store`); sets `password_must_change`, ends their sessions, `user.password_reset` |
| `PUT`/`DELETE /api/v1/users/{id}/roles/{role}` | `access.grant`, the whole role inside the share; never one's own | 204 (idempotent); 409 `last_administrator` |

People routes take browser sessions only (bearer tokens get 403). Someone
outside the editor's share answers 404, exactly like someone who does not
exist. Tests: `tests/people_http.rs` and `tests/people_share_http.rs` (fixture in `tests/common/people.rs`).

### Host groups and labels (spec §5, §13; `src/hosts/groups.rs`, `labels.rs`)

Reads need `access.read` or `host_groups.manage`; host counts and host
lists count only hosts inside the caller's `hosts.read` reach (none
without it). Writes and previews change access for everyone whose role
reaches the group, so they need `host_groups.manage` **and** `hosts.read`
on all hosts (CSRF); otherwise 403 "Changing host groups needs access to
every host". Reads and writes take browser sessions only: bearer tokens
are refused (403). A membership change (`conditions` or `agent_ids` in a
PATCH) also needs every role reaching the group to fit inside the editor's
share on all hosts: each role's host-scope permissions must be held on
every host (Administrators pass), else 403 `permission_denied` with the
share refusal message; a rename or new description skips this. The store
rechecks under its lock that the same roles still reach the group, else
409 `stale_group`. A preview's `gains`/`loses` name, for a
non-administrator, only people the people routes would show them (their
own share); `people_total` still counts everyone.

| Route | Answer |
|---|---|
| `GET /api/v1/host-groups` | `[HostGroupView]`: summary, `conditions`, `membership` sentence, `picked`, `hosts`, `online`, `open_alarms`, `critical`, `roles` (names), `people`, `version` |
| `POST /api/v1/host-groups` | `{name, description?, kind: "rule"\|"manual", conditions?, agent_ids?}` → 201 `HostGroupView` |
| `GET /api/v1/host-groups/{id}` | `HostGroupView` plus `recent` (newest 10 audit changes; no host lists or counts for a caller without global `hosts.read`) |
| `GET /api/v1/host-groups/{id}/hosts?after=&limit=` | `[GroupHostView]`, by hostname, 1–100 (50) |
| `PATCH /api/v1/host-groups/{id}` | `{name?, description?, conditions?, agent_ids?, version}`; a left-out field is unchanged; an automatic group edited becomes a rule group and its key is dismissed → `HostGroupView` |
| `DELETE /api/v1/host-groups/{id}?version=` | 204; removes its rule-set switches |
| `POST /api/v1/host-groups/{id}/preview` | `{conditions}` or `{agent_ids}`, or `{}` for a delete → `{joins, leaves, gains, loses, joins_total, leaves_total, people_total, overrides_removed}` |
| `POST /api/v1/host-groups/preview` | the same for a new group (joins only) |
| `GET /api/v1/hosts/{agent_id}/labels` | `hosts.read` on that host → `{labels, groups: [{asset_group_id, name, kind}]}` |
| `PUT`/`DELETE /api/v1/hosts/{agent_id}/labels/{label}` | `hosts.label` on that host, CSRF → 204 (idempotent) |

Rules: 1–16 conditions on `os_family` (`linux`, `windows`),
`distribution` (`<id> <release>`, lowercase), `hostname` (pattern, `*`
any run) or `ip` (address or CIDR); 1–64 values of 1–255 characters.
Refusals: 400 `invalid_group` (name 1–128, description ≤ 500, body);
422 `invalid_condition` (`field_errors[0].field` names the field, or
`conditions`), `unknown_host`; 404 `group_not_found`, `host_not_found`
(a host outside reach reads the same as a missing one); 409
`group_name_taken`, `stale_group`, `group_in_use` (with `roles`: the
names), `too_many_labels` (32 per host); 400 `invalid_label` (also for `.` and `..`, which the web app refuses before sending). The old
`/api/v1/access-control/asset-groups*` and `/api/v1/agents/{id}/tags*`
routes are gone (404). Tests: `tests/host_groups_http.rs`,
`tests/host_labels_http.rs`.

### Users and passwords (#85)

- `POST /api/v1/users` (`access.users`, CSRF): username (the CLI's rule,
  stored lowercase), display name, optional email and `role_ids` (1–64,
  each inside the creator's share, else 403); a create that loses a race on
  the same name is 409, not 503. The
  answer (201, `no-store`) carries a generated one-time password
  (20 symbols from an unambiguous alphabet, about 99 bits), shown only
  there. 409 when the username is taken. Audited as `user.created` with
  `actor_kind = user`.
- The user then signs in with it. Until they set their own password,
  `GET /api/v1/session` says `password_must_change: true` with no
  capabilities, and every other session route answers 403
  `password_change_required`. The gate sits in `session_capabilities`, the
  one path every session route but `GET /session` and set-password takes.
- `POST /api/v1/session/password` (browser sessions, CSRF): the current
  password and a new one of at least 15 characters that differs from it.
  400 `invalid_current_password`, `weak_password` or `password_unchanged`.
  A wrong current password counts against sign-in's per-account limit (5
  in 15 minutes, shared with sign-in), then 429 `too_many_attempts`, so a
  stolen session cannot guess it faster than sign-in could.
  The change is a compare-and-swap: the credential row is locked and
  replaced only while it still holds the hash the current password was
  checked against, so of two concurrent changes one wins and the other gets
  409 `password_changed_elsewhere` with nothing changed. The Set your
  password screen re-reads the session on focus and after an error, so a
  second tab whose password was already set goes to the console.
  On success (204) the flag is cleared, the user's other sessions are
  signed out, and `auth.password.changed` is audited. The same route is the
  account menu's Change password.

### Roles (spec §4.1–4.4)

`access/roles.rs` (types in `roles_types.rs`):

- `GET /api/v1/permissions` and `GET /api/v1/role-templates`: the
  catalogue and the six templates, to any signed-in person (bearer
  tokens are refused, as for other per-person reads).
- `GET /api/v1/roles` and `GET /api/v1/roles/{role_id}` (`access.read`):
  `RoleView` (permissions, reach `none` / `all` / `groups` with names,
  members, version), Administrator first. The list is also open to
  `service_accounts.manage` (the new-account role picker); a caller let in
  by that alone sees only the roles inside their share. With
  `?held=true` it answers only the caller's own roles, to anyone signed in
  with a browser session (the dashboard Share menu: only roles you hold).
- `POST /api/v1/roles` (201), `PATCH /api/v1/roles/{role_id}` (200, needs
  the `version` read) and `DELETE /api/v1/roles/{role_id}` (204):
  `access.roles` and CSRF. The name is trimmed, 1–64 characters without
  control characters; the description at most 500 (else 400
  `invalid_role` with a field error). Permissions must be closed under
  needs (422 `missing_needs` with `permission` and `needs`); groups are
  1–64 distinct UUIDs that exist (422 `unknown_group`).
- Every write is checked against the editor's share before it reaches
  the store: the new contents for create; for edit and delete the stored
  role too (edit at the version read: a stale one is 409 `stale_role`
  before any share check). A stored permission id the catalogue does not
  know is refused, not ignored, except to an Administrator (they can clean
  such a role up). A refusal is 403 `permission_denied` whose title names the
  permission ("... (View hosts is outside it)").
- 403 `protected_role` for `admin`; 409 `role_name_taken` (any case),
  `stale_role`, `role_in_use` with `holders`. Audited by the store as
  `rbac.role.created`, `rbac.role.updated`, `rbac.role.deleted`.

## Configuration

The router constructor accepts a `platform_store::Pool` and canonical public
origin. The executable constructs it when strict config supplies both
  `database_url` and `public_origin`, and requires that migrations have already
advanced the database to schema 23. Startup never runs migrations. The current
listener is loopback-only and config accepts only canonical HTTP loopback
origins. Login throttling has a five-failure per-account limit and a higher
per-source limit; in reverse-proxy mode, the last address in `X-Forwarded-For`
is used only from an authenticated proxy peer. This supports proxies that
append their observed client address to a forwarded chain; an invalid final
address disables only the per-source bucket.
When auth settings are absent, the executable serves the C0
fail-closed router. `GET /api/v1/agents/summary` now requires a live human
session with `hosts.read`, resolves role bindings on each request, and passes
the effective global or asset-group scope to its SQL aggregate, paginated
list, detail, and certificate queries. Agent and certificate cursors are
bounded and rejected when their filters or scope differ from the current
request. Detail responses include up to 100 certificate metadata rows; the
separate certificate route provides full cursor pagination. Finding and
latest-summary routes require `compliance.read` and use the same active SQL
scope; latest-finding list/detail and history list/event routes use that scope
in SQL. Their bounded cursors are tied to the active filters and scope, and
history requires a lower time bound for partition pruning. Latest-finding
triage reads and writes use the same finding scope; writes require
`compliance.triage`, CSRF, exact Origin, same-origin Fetch Metadata, and a
matching ETag `If-Match`. State, assignment, note, history, and audit are
committed atomically. Audit retention
reads require `audit.read`; updates require global `audit.retention.manage`,
CSRF, exact Origin, same-origin Fetch Metadata, and a version-matching
`If-Match`. Other control-plane data routes remain unavailable.

## Failure behaviour

Invalid credentials never reveal whether an account exists. Database errors
are reduced to the generic authentication-unavailable problem. Capabilities
are read from the database on every request, for sessions and bearer tokens
alike (`rbac::principal_capabilities`, see console-rbac.md): a role edit
reaches an issued token at its next request. A permission id the catalogue
does not know grants nothing. A role's host permissions apply on its reach;
endpoints must still enforce that scope in SQL before serving agent or
finding records.

## How to test

Run `cargo test --offline -p openvibes-console` for API contract and router
checks. The PostgreSQL-backed HTTP journey covers login, account-enumeration
failure shape, session rotation, and logout (`--test users_http`: New
user, the forced change, self-service change):
`OPENVIBES_TEST_DATABASE_URL=… cargo test --offline -p openvibes-console
--test auth_http`. Store transaction coverage uses the same isolated test
cluster with `cargo test --offline -p platform-store --test console_auth`.
