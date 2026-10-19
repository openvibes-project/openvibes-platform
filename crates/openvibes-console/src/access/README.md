# src/access

Who may do what in the console: sign-in and the session, the checks every area's handlers run, roles, people and their roles, service accounts, host groups and host tags.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules, the public names of its types, and `routes()`: the paths this area serves. |
| `guard.rs` | Session and permission checks: the caller, their capabilities and scope, and the 401/403/503 answers. |
| `auth.rs` | Session, password and CSRF primitives. |
| `auth_tests.rs` | Tests for those primitives. |
| `auth_first.rs` | Authenticates every `/api` request before its handler runs. |
| `rbac.rs` | Turns held roles (from the database, per request) into capabilities and their host scope; Administrator holds everything. |
| `permission.rs` | `Permission`, the 48 stable permission identifiers, and `PermissionScope`. |
| `catalogue.rs` | The permission catalogue: area, console text, column, scope and needs of each permission; `with_needs`. |
| `templates.rs` | The six role templates and their permissions. |
| `users.rs` | Setting one's own password, and the one-time password generator. |
| `people.rs` | The People API: list, a person's page, add and edit details, filtered to the editor's share; shared lookups and answers. |
| `people_admin.rs` | Disable, enable and reset password for a person inside the editor's share. |
| `people_roles.rs` | Giving and removing roles for people and service accounts. |
| `people_types.rs` | Request and response types of the People API and the host-group list. |
| `editor.rs` | Who is changing access (`caller`), and the share checks on whole stored roles (`role_fits`, `roles_fit`, `within_share`). |
| `session.rs` | The browser session read. |
| `login.rs` | Sign-in: the pre-login challenge, login and logout. |
| `throttle.rs` | Sign-in throttle buckets and failure limits, per account and per source address. |
| `service_accounts.rs` | Service accounts: list (filtered to the share), create, disable. |
| `service_tokens.rs` | Service-account tokens: list, create, revoke. |
| `roles.rs` | The roles API: the catalogue, templates, and role list, read, create, edit and delete, each write checked against the editor's share. |
| `roles_types.rs` | Request and response types of the roles API. |
| `share.rs` | The share check: a role fits only inside the editor's own permissions and reach (spec §4.4). |
| `asset_groups.rs` | Host groups: list (`GET /v1/host-groups`); the old tag-selector create and update answer 410 `moved` (schema 53). |
| `tags.rs` | Host tags: gone with schema 53; preview and apply answer 410 `moved`. |
| `session_types.rs` | Request and response types of sign-in, the session and users. |
| `grant_types.rs` | Request and response types of asset groups, host tags and service accounts. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
