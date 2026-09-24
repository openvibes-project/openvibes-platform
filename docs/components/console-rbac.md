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
active local-user bindings, and exact asset-group selectors. Viewing it emits
`access_control.viewed`. SQL still enforces resolved asset scope before any
filtering, aggregation, pagination, or facet calculation.

Run `cargo test -p openvibes-console rbac::tests`.
