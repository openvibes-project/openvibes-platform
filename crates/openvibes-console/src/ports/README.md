# src/ports

Ports in the console: the Ports list (one row per port) and, from the next task of step 5e, a port's page.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules and `routes()`: the paths this area serves. |
| `list_page.rs`, `list_page_types.rs` | `GET /v1/port-list`: the list by port, its parameters, validation, answer types and the call into the store. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
