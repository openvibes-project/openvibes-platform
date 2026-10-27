# src/ports

Ports in the console: the Ports list (one row per port) and a port's page.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules and `routes()`: the paths this area serves. |
| `page.rs`, `page_types.rs` | `GET /v1/ports/{protocol}/{port}/summary` and `/hosts`: a port's page, its actions and answer types. |
| `list_page.rs`, `list_page_types.rs` | `GET /v1/port-list`: the list by port, its parameters, validation, answer types and the call into the store. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
