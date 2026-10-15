# src

The console server: the HTTP API and auth routes, the session and permission checks, and the listeners that serve them. The code is moving into one folder per area of the console; the files still at the top move in later steps.

| File | What it does |
|---|---|
| `lib.rs` | The crate's modules and its public names (routers, config, API types). |
| `main.rs` | The `openvibes-console` binary: reads `console.toml` and runs the server. |
| `server.rs` | The listeners: TLS, trusted peers, and serving the routers. |
| `config.rs` | `console.toml`: listeners, transport, origin and agent install settings. |
| `router.rs` | The handlers not yet moved to an area folder, and helpers several areas share. |
| `api.rs` | The API's request and response types. |
| `about.rs` | The About page: versions and the newer-release check. |
| `about_tests.rs` | Tests for the About page and the newer-version check. |
| `assistant.rs` | The assistant: its runtime and the lookups it may run. |
| `assistant_internet.rs` | The administrator's switch for the assistant's internet lookups. |
| `coverage.rs` | MITRE ATT&CK coverage of the published rules. |
| `dashboards.rs` | Dashboards: layout validation and handlers. |
| `fetch_client.rs` | The assistant's internet lookups through `openvibes-fetch`. |
| `metrics.rs` | Count history per day for the overview. |
| `rule_assignment.rs` | Which asset groups run each assignable rule set. |
| `rule_drafts.rs` | Draft rules for the site's own rule sets. |
| `rule_test.rs` | Tests a rule against one host's facts. |
| `seeded.rs` | Fixed demo data for the loopback development listener (`dev-seed`). |
| `access/` | Who may do what: sign-in, roles, users, service accounts, role bindings, asset groups, host tags. |
| `alarms/` | Alarms: list, detail and triage, suppressions, detection evidence. |
| `assistant/` | The assistant's tests against a database and a fake fetch socket. |
| `audit/` | The audit trail: events, CSV export, retention. |
| `cases/` | Cases: one investigation's record, split by list, items and lookups. |
| `compliance/` | Findings, finding groups, history, triage, bulk triage, triage detail. |
| `bin/` | Tools built with the crate. |
| `hosts/` | Hosts: agents, certificates, enrollment tokens, install package, software, ports, presence, fleet. |
| `http/` | Router assembly, route table, middleware, web app files, problems, OpenAPI. |
| `vulnerabilities/` | Vulnerability summary, list and advisory detail. |

More: [docs/components/openvibes-console.md](../../../docs/components/openvibes-console.md)
