# src/audit

The audit trail in the console: the event list, its CSV export and the retention policy.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules, the public names of its types, and `routes()`: the paths this area serves. |
| `events.rs` | The audit event list, filtered and paged. |
| `export.rs` | The filtered audit events as a CSV download. |
| `retention.rs` | The audit retention policy: read and update. |
| `query.rs` | Query parameters and cursor tokens of the list and the export. |
| `types.rs` | Request and response types of the events and the retention policy. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
