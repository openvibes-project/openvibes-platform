# src/services

Services in the console: the Services list (one row per unit) and a service's page.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules and `routes()`: the paths this area serves. |
| `page.rs`, `page_types.rs` | `GET /v1/services/{unit}/summary` and `/hosts`: a service's page, its actions and answer types. |
| `list_page.rs`, `list_page_types.rs` | `GET /v1/service-list`: the list by unit, its parameters, validation, answer types and the call into the store. |

More: [docs/components/console-services.md](../../../../docs/components/console-services.md)
