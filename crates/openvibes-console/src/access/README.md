# src/access

Who may do what in the console: sign-in and the session, the checks every area's handlers run, roles, users, service accounts, role bindings, asset groups and host tags.

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
| `users.rs` | Console users and setting one's own password. |
| `session.rs` | The browser session read. |
| `login.rs` | Sign-in: the pre-login challenge, login and logout. |
| `throttle.rs` | Sign-in throttle buckets and failure limits, per account and per source address. |
| `service_accounts.rs` | Service accounts: list, create, disable. |
| `service_tokens.rs` | Service-account tokens: list, create, revoke. |
| `share.rs` | The share check: a role fits only inside the editor's own permissions and reach (spec §4.4). |
| `bindings.rs` | Role bindings: create and revoke. |
| `asset_groups.rs` | Asset groups: create and update. |
| `tags.rs` | Host tags: preview and apply. |
| `inventory.rs` | The access inventory: users, roles, bindings and asset groups. |
| `session_types.rs` | Request and response types of sign-in, the session and users. |
| `grant_types.rs` | Request and response types of the access inventory, bindings, asset groups, host tags and service accounts. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
