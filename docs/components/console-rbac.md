# Console RBAC resolver

`crates/openvibes-console/src/rbac.rs` defines the built-in Viewer, Analyst,
Operator, and Admin role permissions and resolves a set of role bindings into
the `EffectiveCapability` DTOs returned by the session API. Agent and finding
permissions can be scoped to one or more asset groups. Scoped bindings ignore
control-plane permissions; a global grant for a permission dominates any
scoped grants. Group IDs are deduplicated and sorted for stable output.

The resolver is pure and has no configuration or database access. Persisted
bindings are loaded from PostgreSQL for each authenticated request. The
global-permission `GET /api/v1/access-control` view returns role permissions,
active local-user bindings, enabled user options, and exact asset-group
selectors. Viewing it emits `access_control.viewed`. Global `rbac.manage`
users can create or revoke local-user bindings through POST/DELETE under
`/api/v1/access-control/bindings`; both require exact Origin, same-origin
Fetch Metadata, and the current session CSRF token. Binding changes and their
audit rows commit atomically. Revoke prevents removal of the final enabled
global Admin binding under a transaction advisory lock. The Access page exposes these
controls only when the current session has global `rbac.manage`. SQL still
enforces resolved asset scope before any filtering, aggregation, pagination,
or facet calculation.

Global `asset_groups.manage` administrators can create groups with one to 32
exact selectors or replace an existing group's name and full selector set
through POST/PUT under `/api/v1/access-control/asset-groups`. Selector keys are
unique within a group and key/value lengths follow the schema limits. Changes
require the same Origin, Fetch Metadata, and CSRF checks, and their selector
data and audit detail commit in one transaction. Selector writes serialize
with agent tag changes. The Access page provides create/edit forms; editing
requires explicit confirmation because it can change membership and scoped
visibility.

Run `cargo test -p openvibes-console rbac::tests`.
