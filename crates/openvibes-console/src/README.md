# src

The console server: the HTTP API and auth routes, the session and permission checks, and the listeners that serve them. Each area of the console has its own folder; the files at the top are the crate root, the binary, the configuration and the About page.

| File | What it does |
|---|---|
| `lib.rs` | The crate's modules and its public names (routers, config, API types). |
| `main.rs` | The `openvibes-console` binary: reads `console.toml` and runs the server. |
| `config.rs` | `console.toml`: listeners, transport, origin and agent install settings. |
| `about.rs` | The About page: versions and the newer-release check. |
| `about_tests.rs` | Tests for the About page and the newer-version check. |
| `host_pages.rs` | What the port and service page routes share: the Related reach, the actions' reach checks and the Hosts query. |
| `access/` | Who may do what: sign-in, roles, users, service accounts, role bindings, asset groups, host tags. |
| `alarms/` | Alarms: list, the alarm page summary, detail and triage, suppressions, detection evidence. |
| `assistant/` | The assistant: chat endpoints, runtime, lookups, internet switch. |
| `audit/` | The audit trail: events, CSV export, retention. |
| `cases/` | Cases: one investigation's record, split by list, items and lookups. |
| `compliance/` | Findings, finding groups, history, triage, bulk triage, triage detail. |
| `bin/` | Tools built with the crate. |
| `dashboards/` | Dashboards and the count history behind their widgets. |
| `lists/` | Saved views and hidden columns of the list pages, per person. |
| `hosts/` | Hosts: agents, certificates, enrollment tokens, install package, software, ports, presence, fleet. |
| `http/` | Router assembly, route table, middleware, web app files, problems, OpenAPI. |
| `ports/` | Ports: the list (`port-list`) and a port's page (summary and hosts). |
| `services/` | Services: the list (`service-list`) and a service's page (summary and hosts). |
| `software_pages/` | Software: the list (`software-list`) and a package's page (summary and hosts). |
| `rules/` | Rule sets and bundles, assignment, draft rules, rule tests, ATT&CK coverage. |
| `settings/` | General settings: the typed list and changing one value. |
| `sso/` | Single sign-on: setting checks, pasted identity provider certificates, our SAML metadata. |
| `server/` | The listeners: TLS, trusted peers, and serving the routers. |
| `seeded/` | Fixed demo data for the loopback development listener (`dev-seed`). |
| `vulnerabilities/` | Vulnerability summary, list and advisory detail. |

More: [docs/components/openvibes-console.md](../../../docs/components/openvibes-console.md)
