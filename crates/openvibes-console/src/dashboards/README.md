# src/dashboards

Dashboards over `/api/v1` and the count history behind their widgets.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules, the public names of its types, and `routes()`: the paths this area serves. |
| `dashboard.rs` | List, create, read, update, delete and share a dashboard. |
| `home.rs` | The dashboard that opens first for the signed-in user. |
| `layout.rs` | Validates a dashboard's name and layout (bounded, allow-listed widget types). |
| `responses.rs` | The dashboard view, ETag and refusal answers shared by the handlers. |
| `types.rs` | Request and response types of dashboards. |
| `metrics.rs` | Count history per day and top hosts for the overview. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
