# src

The console server: the HTTP API and auth routes, the session and permission checks, and the listeners that serve them. The code is moving into one folder per area of the console; the files still at the top move in later steps.

| File | What it does |
|---|---|
| `lib.rs` | The crate's modules and its public names (routers, config, API types). |
| `main.rs` | The `openvibes-console` binary: reads `console.toml` and runs the server. |
| `server.rs` | The listeners: TLS, trusted peers, and serving the routers. |
| `config.rs` | `console.toml`: listeners, transport, origin and agent install settings. |
| `about.rs` | The About page: versions and the newer-release check. |
| `about_tests.rs` | Tests for the About page and the newer-version check. |
| `fetch_client.rs` | The assistant's internet lookups through `openvibes-fetch`. |
| `seeded.rs` | Fixed demo data for the loopback development listener (`dev-seed`). |
| `access/` | Who may do what: sign-in, roles, users, service accounts, role bindings, asset groups, host tags. |
| `alarms/` | Alarms: list, detail and triage, suppressions, detection evidence. |
| `assistant/` | The assistant: chat endpoints, runtime, lookups, internet switch. |
| `audit/` | The audit trail: events, CSV export, retention. |
| `cases/` | Cases: one investigation's record, split by list, items and lookups. |
| `compliance/` | Findings, finding groups, history, triage, bulk triage, triage detail. |
| `bin/` | Tools built with the crate. |
| `dashboards/` | Dashboards and the count history behind their widgets. |
| `hosts/` | Hosts: agents, certificates, enrollment tokens, install package, software, ports, presence, fleet. |
| `http/` | Router assembly, route table, middleware, web app files, problems, OpenAPI. |
| `rules/` | Rule sets and bundles, assignment, draft rules, rule tests, ATT&CK coverage. |
| `vulnerabilities/` | Vulnerability summary, list and advisory detail. |

More: [docs/components/openvibes-console.md](../../../docs/components/openvibes-console.md)
