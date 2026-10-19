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
  ignored. A group reach never covers imported hosts (`agents.status =
  'imported'`, from export files): only a role reaching all hosts sees them.
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
**platform** scope applies everywhere (`'global'`): a role holding one grants
it whatever the role's reach, even a role reaching no host. Host data a
platform route shows (testing a site rule on a host, the site fleet view)
still keeps to the caller's `hosts.read` reach. Needs are transitive and acyclic; `with_needs` closes a set.
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
`site_rules.read`, the fleet's hosts within `hosts.read`; draft check, save
and delete `site_rules.write`; test on a host `site_rules.test` plus
`hosts.read` reaching that host (else 404 `host_not_found`); publishing drafts `site_rules.publish` (the signer
checks the same id); signed bundle preview and publish `rules.publish`;
alarm suppression list `alarms.suppressions.read`; creating or editing a
case `cases.write`, and setting or changing its assignee (and the assignee
list) `cases.assign`; enrollment tokens `tokens.manage`, the agent installer
`tokens.installer`; creating users `access.users`; bindings `access.grant`;
host groups and host tags `host_groups.manage`; service accounts
`service_accounts.manage`, their tokens `service_accounts.tokens`.

People (spec §4.4, §9.1; `access/people.rs`, `people_roles.rs`): `GET
/api/v1/users` (`access.read`) and `GET /api/v1/users/{id}` (`access.read`,
or one's own page) return, to an editor without Administrator, only people
whose roles all fit inside the editor's share (`editor::roles_fit`, built
on `share::all_fit`); anyone else answers 404 exactly like someone who does
not exist. The Service accounts list is filtered the same way. Giving or
removing a role (`PUT`/`DELETE /api/v1/users/{id}/roles/{role}` and the
service-account equivalent) needs `access.grant` and the whole role inside
the editor's share; nobody changes their own roles, and nobody disables
themself. These routes take browser sessions only (CSRF on writes); a
session that must still set its password is refused. The last enabled
Administrator is kept by the store under the access-binding advisory lock
(409 `last_administrator`). SQL still
enforces resolved asset scope before any filtering, aggregation, pagination,
or facet calculation.

Since schema 53 tag-selector groups and host tags are gone: membership is
decided by the SQL function `console_host_in_group` (platform-store.md "Host
groups"), and the old POST/PUT under `/api/v1/access-control/asset-groups`
and the agent tag routes answer 410 `moved` until the host-group and label
routes arrive.

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

## Share check

`access/share.rs` (pure) decides whether a role (permissions plus reach) fits inside an editor's own capabilities: every permission must be held, and host permissions must cover the role's reach (reaches from several held roles combine; platform permissions ignore reach). Refusals name the permission in console words. The roles API (`access/roles.rs`) calls it on every create, edit and delete, and the people and service-account handlers on every role given, removed or set at creation, always with the capabilities of whoever made the request, read unfiltered from the database (`editor::caller`). The session's list (`GET /api/v1/session`) leaves out `assistant.use` while no assistant is set up, so the web's copy of the check (`fitsShare`) does not judge that permission; the server still does.

## Upgrading

Existing roles are kept: migrations 51 and 52 (both are marked as needing a backup) rename the permissions and turn each holder's scoped grants of one role into a role of its own, such as "Operator (Lab)", reaching those groups, so nobody gains or loses access (`platform-store/tests/custom_roles.rs` compares access before and after).

## Live check

`scripts/test-console-e2e.sh` (real console, throwaway database) runs the two-team journey of spec §15 (`web/e2e/live/teams.spec.ts`): an Administrator makes "Linux team" and "Windows team" from the Analyst template, each on a host group made through the asset-group API (`scripts/console-e2e-server.sh` seeds two enrolled hosts tagged `os=linux` and two `os=windows`, each with one finding and one alarm); each person sees only their two hosts in Hosts, Compliance and Alarms and has no Roles tab; the Linux person's bulk triage changes linux-1 and leaves windows-1 as it was; with a Team lead role on Linux (plus `access.users`) the Linux person adds someone with "Linux team", is not offered "Windows team", and the API refuses it with "You can only give roles that fit inside your own access (… is outside it)". A role on a group with no hosts sees the empty Alarms view.
