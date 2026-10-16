# Console RBAC resolver

`crates/openvibes-console/src/access/rbac.rs` turns the roles a principal
holds into the `EffectiveCapability` DTOs the guards and the session API use
(spec 2026-10-16-roles-permissions-design.md §4.3, §6). Roles live in the
database (schema 52): each has permissions and a reach (all hosts, some
host groups, or none).

- `principal_capabilities(client, Principal)` is the one place bindings
  become capabilities: bearer tokens, sessions and `GET /api/v1/session` all
  call it. It loads the grants with `console_roles::grants` (one query) on
  every request; there is no cache, so a role edit or a revoked binding
  applies at the next request.
- `resolve_capabilities(&[Grant])` is pure. A **platform** permission is
  global when any held role has it, whatever its reach. A **host**
  permission applies on the union of the reaches of the roles holding it;
  reach all dominates, reach none grants it nowhere. Group ids are
  de-duplicated and sorted. Stored ids the catalogue does not know are
  ignored.
- **Administrator** (`ADMIN_ROLE`, `admin`) holds all 48 permissions
  globally, whatever its stored rows say.
- Creating a user or a service account checks the role id in the database;
  an unknown one is 400 `unknown_role`.
- The triage assignee check (alarms, findings, vulnerabilities;
  `console_roles::assignee`) accepts an enabled user holding the area's
  `*.triage` permission through an active role that reaches some host
  (all hosts or a group), or an Administrator.
- The web role pickers (new user, new service account, granting a role)
  have no default: the submit stays disabled until a role is chosen.
- Settings › Rule sets fetches where sets run only with
  `rules.assignment.read`; without it the list has no "Runs on" column.
- `cases.assign` is checked held-or-not, whatever its reach: the case is
  already limited by the scope of `cases.write`. (Case visibility by items'
  hosts, spec §6, comes in a later step.)
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
them equal to the Rust ones, and `auth_http.rs` checks the database scopes
against Rust and that a fresh Administrator holds all 48.

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
views, `site_rules.read`). Admin holds all 48. Since schema 52 the roles are
rows in the database and only Administrator is built in.

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

The
global-permission `GET /api/v1/access-control` view returns role permissions,
active local-user bindings, enabled user options, and exact asset-group
selectors. Viewing it emits `access_control.viewed`. Global `access.grant`
users can create or revoke local-user bindings through POST/DELETE under
`/api/v1/access-control/bindings`; both require exact Origin, same-origin
Fetch Metadata, and the current session CSRF token. Binding changes and their
audit rows commit atomically. Revoke prevents removal of the final enabled
Administrator binding under a transaction advisory lock. The Access page exposes these
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
database configured) to cover resolution, a service token following role
edits (`service_token_follows_role_edits`), authenticated group
creation/update and the agent-tag preview, stale-preview rejection, apply,
and audit journey. `cases_http`'s
`writing_cases_without_cases_assign_cannot_set_the_assignee` covers
`cases.assign`. The console HTTP tests create the roles they bind with
`tests/common` (`ensure_role` for the former viewer, analyst and operator,
`create_role`, and `scope_bindings`, which gives a binding a copy of its
role reaching one group, as migration 52 does).
