# src/software_pages

Software in the console: the Software list (one row per package name, rpm and dpkg together) and a package's page.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules and `routes()`: the paths this area serves. |
| `page.rs`, `page_types.rs` | `GET /v1/software-pages/{name}/summary` and `/hosts`: a package's page, its actions and answer types. |
| `list_page.rs`, `list_page_types.rs` | `GET /v1/software-list`: the list by name, its parameters, validation, answer types and the call into the store. |

More: [docs/components/console-software.md](../../../../docs/components/console-software.md)
