# src/seeded

Fixed demo data for the loopback development listener (`dev-seed`): deterministic, permission-aware read models. Request headers choose the demo persona and state.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules and `router()`: the demo's read routes, never cached. |
| `persona.rs` | The demo persona and mode chosen by request headers, and the permission check every handler runs. |
| `repository.rs` | The fixture: 50,000 generated agents and their findings, and the reads made of them. |
| `filters.rs` | Query filters of the agent and finding lists, and their cursor paging. |
| `responses.rs` | The demo's problem answers and its no-store header. |
| `hosts.rs` | Agent summary, list and detail. |
| `compliance.rs` | Finding summary, list, groups, group endpoints, and one finding. |
| `vulnerabilities.rs` | Vulnerability summary, list and advisory detail. |
| `audit.rs` | Audit events and their CSV export. |
| `access.rs` | The access inventory. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
