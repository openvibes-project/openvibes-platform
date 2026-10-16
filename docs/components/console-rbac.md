# Console RBAC resolver

`crates/openvibes-console/src/access/rbac.rs` defines the built-in Viewer, Analyst,
Operator, and Admin role permissions and resolves a set of role bindings into
the `EffectiveCapability` DTOs returned by the session API. Agent and finding
permissions can be scoped to one or more asset groups. Scoped bindings ignore
control-plane permissions; a global grant for a permission dominates any
scoped grants. Group IDs are deduplicated and sorted for stable output.
## The permission catalogue (schema 51)

`crates/openvibes-console/src/access/catalogue.rs` declares the 48
permissions once (spec 2026-10-16-roles-permissions-design.md §3): for each
its id (wire and database name), area, console text, matrix column (View,
Change, Export, Approve and publish), scope and needs. **Host** scope applies
on the hosts the granting binding reaches (database `scope_class = 'agent'`);
**platform** scope applies everywhere (`'global'`) and a scoped binding does
not grant it. Needs are transitive and acyclic; `with_needs` closes a set.
`Permission` (`permission.rs`) has one variant per row with `id()` and
`from_id()`. `templates.rs` holds the six role templates of §4.2 (Viewer,
Analyst, Operator, Team lead, Auditor, Rule author), each closed under needs.
`export_openapi --permissions` and `--templates` write
`web/src/api/permissions.json` and `templates.json`; `api_contract.rs` keeps
them equal to the Rust ones, and `auth_http.rs` checks the database scopes and
built-in role rows against Rust.

Migration 51 replaced the old ids: `agents.*` became `hosts.*`,
`cases.manage` became `cases.write` and `cases.assign`, `tokens.create` and
`tokens.revoke` became `tokens.manage` and `tokens.installer`, `rules.upload`
became `rules.publish`, `rules.write` became `rules.assignment.write` and
`site_rules.*`, `rbac.read` became `access.read`, `rbac.manage` became
`access.users`, `access.roles` and `access.grant`, `asset_groups.manage`
became `host_groups.manage`, and `service_accounts.manage` gained
`service_accounts.tokens`. Every role kept what it could do and gained the
needs of what it holds, the export of what it reads, and the new views that
cover what it could already see (`alarms.suppressions.read`, the rule-set
views, `site_rules.read`). Admin holds all 48. The four built-in roles stay
in `rbac.rs` until roles move into the database; their sets are the mapped
old sets, closed under needs.

Which permission each route checks: rule-set list and bundle history
`rules.read`; switches `rules.assignment.read` / `rules.assignment.write`;
coverage and the ATT&CK catalog `rules.coverage.read`; the assistant's rule
contents `rules.contents.read`; draft list, fleet and publish preview
`site_rules.read`; draft check, save and delete `site_rules.write`; test on a
host `site_rules.test`; publishing drafts `site_rules.publish` (the signer
checks the same id); signed bundle preview and publish `rules.publish`;
alarm suppression list `alarms.suppressions.read`; creating or editing a
case `cases.write`, and setting or changing its assignee (and the assignee
list) `cases.assign`; enrollment tokens `tokens.manage`, the agent installer
`tokens.installer`; creating users `access.users`; bindings `access.grant`;
host groups and host tags `host_groups.manage`; service accounts
`service_accounts.manage`, their tokens `service_accounts.tokens`.

The resolver is pure and has no configuration or database access. Persisted
bindings are loaded from PostgreSQL for each authenticated request. The
global-permission `GET /api/v1/access-control` view returns role permissions,
active local-user bindings, enabled user options, and exact asset-group
selectors. Viewing it emits `access_control.viewed`. Global `access.grant`
users can create or revoke local-user bindings through POST/DELETE under
`/api/v1/access-control/bindings`; both require exact Origin, same-origin
Fetch Metadata, and the current session CSRF token. Binding changes and their
audit rows commit atomically. Revoke prevents removal of the final enabled
global Admin binding under a transaction advisory lock. The Access page exposes these
controls only when the current session has global `access.grant`
(New user: `access.users`). SQL still
enforces resolved asset scope before any filtering, aggregation, pagination,
or facet calculation.

Global `host_groups.manage` administrators can create groups with one to 32
exact selectors or replace an existing group's name and full selector set
through POST/PUT under `/api/v1/access-control/asset-groups`. Selector keys are
unique within a group and key/value lengths follow the schema limits. Changes
require the same Origin, Fetch Metadata, and CSRF checks, and their selector
data and audit detail commit in one transaction. Selector writes serialize
with agent tag changes. The Access page provides create/edit forms; editing
requires explicit confirmation because it can change membership and scoped
visibility.

Run `cargo test -p openvibes-console --lib access::`,
`cargo test -p platform-store --test permission_catalogue` and
`cargo test -p openvibes-console --test auth_http` (with the PostgreSQL test
database configured) to cover authenticated group creation/update and the
agent-tag preview, stale-preview rejection, apply, and audit journey.
