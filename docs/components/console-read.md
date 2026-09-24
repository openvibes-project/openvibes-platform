# Console read models

`platform_store::console_read` supplies bounded, typed read queries for
the OpenVIBES web console. It contains all SQL for agent summaries and pages,
certificate metadata, latest findings, finding summaries, and retained finding
history. The console crate converts these records to its HTTP DTOs and applies
authentication and scope rules before calling them. The unscoped functions
are global read primitives. `agents_in_scope` and `agent_in_scope` enforce
agent visibility in SQL for the supplied global or asset-group scope.

## Interfaces

- `agent_summary` and `finding_summary` each use one deliberate aggregate
  query; collection endpoints do not compute exact totals.
- `agents` uses a stable cursor over last-seen time descending, nulls last, and
  agent ID ascending. The state filter is allow-listed and stale state is
  computed against the supplied time.
- `AgentScope::AssetGroups` matches an agent when every exact tag selector in
  any authorized asset group matches. Empty group sets match no agents.
  `agent_summary_in_scope`, `agents_in_scope`, and `agent_in_scope` apply that
  predicate before aggregation, status filtering, cursor traversal, ordering,
  and limiting. `agent_in_scope` hides out-of-scope IDs as absent.
- `certificates_in_scope` verifies the owning agent's scope in the same SQL
  query before paging certificate metadata. Out-of-scope agents return an
  empty page. Findings still need scoped variants; the authenticated console
  does not expose production data routes yet.
- `agent` reads one agent. `certificates` pages certificate serial and
  validity metadata and never selects the stored PEM chain.
- `latest_findings` and `latest_finding` read the complete snapshot in
  `current_findings`, including host label and display fields. They do not
  join an event partition to render current state.
- `finding_history` requires a lower time bound for partition pruning and
  supports bounded exact agent, rule-set, and rule filters. `finding_event`
  uses the event table's `(observed_day, finding_id)` primary key.
- Every list requires `PageLimit`, which accepts 1–100 rows, and fetches at
  most one extra row to decide whether to return a continuation cursor. The
  console serializes cursors and binds them to filters and authorization.
- `schema_is_current` is false for an empty, older, or newer schema; callers
  must keep readiness false and must not serve data unless it returns true.

## Configuration and failure behaviour

The functions use a `platform_store::Client` from the bounded pool. PostgreSQL
or query failures return the fixed `StoreError` categories. Invalid page sizes
cannot be represented as `PageLimit`. The module does not log query values,
apply user permissions, or expose raw SQL errors.

## How to test

```sh
eval "$(scripts/test-db.sh)"
cargo test --locked -p platform-store --test console_read -- --nocapture
```

The PostgreSQL acceptance test loads 50,000 agents, records the plans and
latency for the paged list and summary queries, and checks cursor traversal,
latest snapshots, and history partition keys.

## Acceptance measurement

The local PostgreSQL 18.6 throwaway-cluster run with 50,000 agents selected
`agents_console_last_seen_idx` for the ordered first page: 51 rows took
0.051 ms execution time with 54 shared buffers. Thirty client round trips for
the 50-row page measured p50 496 µs and p95 568 µs. The deliberate summary
aggregate used a sequential scan of 50,000 rows (758 shared buffers, 9.158 ms
execution); its thirty client round trips measured p50 6.910 ms and p95 7.527
ms. These are local warm-cache observations, not a deployment latency target.
