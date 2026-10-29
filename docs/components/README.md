# Platform Components

One page per crate or service: purpose, interfaces, configuration, failure
behaviour, and how to test. Updated in the same change as the component.

| Component | Kind | Status | Page |
|---|---|---|---|
| `platform-config` | library | built (PM0) | [platform-config.md](platform-config.md) |
| `platform-pki` | library | CA hierarchy, CSR checks, client certificates (PM2) | [platform-pki.md](platform-pki.md) |
| `platform-password` | library | console password rules, Argon2id hashing and verification, shared by the console and the signer (#107) | [platform-password.md](platform-password.md) |
| `platform-settings` | library | the settings the console changes for the whole platform (general, `vulns.*`): key, wording, type, range, default, live or restart, and the check of a new value, shared by the console and the services | [platform-settings.md](platform-settings.md) |
| `platform-store` | library | schema 71, general settings, rule-set assignment, assistant internet lookups, network devices and device alarms, imported hosts, OSV packages, vulnerability data/enrichment and persistent matcher retry state, rule distribution, finding/alarm detection evidence, console identity/sessions, triage, assistant and vulnerability permissions, console role grants, partitions, status, tokens, agents, CA certificates (PM1, PM2, VM0–VM5, OSV D2–D5, C2–C4, P17) | [platform-store.md](platform-store.md) |
| `platform_store::console_auth` | module | local identity/session store, access inventory, asset-group/tag changes, enrollment tokens, and service-account bearer tokens (C3) | [console-auth-store.md](console-auth-store.md) |
| `platform_store::console_read` | module | bounded, cursor-paginated console read models and SQL-enforced scoped agent reads (C2/C3) | [console-read.md](console-read.md) |
| `platform_store::audit` | module | audit event reads/writes, versioned retention policy, and bounded expiry cleanup (C3) | [console-audit.md](console-audit.md) |
| `platform-agent-server` | library | shared agent-facing server: TLS, auth, limits, logs, health, drain (SP2 DM0) | [platform-agent-server.md](platform-agent-server.md) |
| `platform-assistant` | library | assistant configuration, OpenAI-compatible backend client, capability probe (AS1); scoped lookups, orchestrator, output sanitising (AS2); evaluation fleet, question set, gate (AS3) | [platform-assistant.md](platform-assistant.md) |
| `platform-host` | library | host operations for the admin TUI: unit allow-list, systemd backend (services, start/stop/restart, logs) (TUI PR 1) | [platform-host.md](platform-host.md) |
| `openvibes-admin` | CLI | migrate, status, maintenance (PM1); ca, token, agent (PM2); rules (SP2); assistant check, eval (AS3); local console user bootstrap and administration (C3); local model install/check (AS5) | [openvibes-admin.md](openvibes-admin.md) |
| `openvibes-llm` | optional service, loopback 18430 | pinned `llama-server` (CPU, Vulkan) for the assistant, hardened unit, model digest check (AS5) | [openvibes-llm.md](openvibes-llm.md) |
| `openvibes-signer` | service, Unix socket | signs the site's own rule sets after checking the user's password and `site_rules.publish` itself; own DB role, journal audit, version state (#107) | [openvibes-signer.md](openvibes-signer.md) |
| `openvibes-picture` | service (socket-activated, one process per upload) and library | converts an uploaded profile picture to 256 px and 64 px WebP in a sandbox with no files and no network; size, type, pixel and frame limits | [openvibes-picture.md](openvibes-picture.md) |
| `openvibes-fetch` | service (socket-activated, one process per request) and library | the only outbound requests of the assistant's opt-in internet lookups: OSV and Bodhi references (level 1), web search through the admin's SearXNG (level 2), query filter, deadlines | [openvibes-fetch.md](openvibes-fetch.md) |
| `openvibes-ingest` | service, port 18423 | enroll, renew, heartbeat, findings, limits, health (PM3) | [openvibes-ingest.md](openvibes-ingest.md) |
| `integration-agent` | test script | real agent against ingest: enroll, deliver exactly once, restart, renew, revoke, re-enroll (PM4); against distribution: poll, update, outage, refused bundle, revoke (SP2) | [integration-agent.md](integration-agent.md) |
| `openvibes-vulns` | service (health 18483) and library | Fedora advisories fetched and verified hourly, exact RPM version matching, persistent retries for pending host matches and vulnerability lifecycle (VM2) | [openvibes-vulns.md](openvibes-vulns.md) |
| `openvibes-netlog` | service (UDP 514, health 18484) | UniFi IPS/IDS events from registered devices become alarms; plain syslog and other events are dropped and counted (spec 2026-10-10) | [openvibes-netlog.md](openvibes-netlog.md) |
| `packaging` | RPMs | ingest, distribution, vulns, admin, agent, console, and optional local LLM packages; offline console frontend cache pin, hardened units, maintenance timer; whole platform under systemd (PM4, SP2, M6a, VM3, C5, AS5) | [packaging.md](packaging.md) |
| `offline kit` | tar per release | the platform, rule sets and Fedora's dependency closure in one signed tar with an installer, tested with no network (`packaging/offline/`, `scripts/*offline*`) | [offline-kit.md](offline-kit.md) |
| `load` | test tool | openvibes-load generator and runner: ingest (PM5), distribution mode (SP2) | [load.md](load.md) |
| `openvibes-console` | web application and `/api/v1` | C3 auth/control plane; TLS 1.3, trusted loopback/Unix-socket proxy, enforced CSP/HSTS; offline RPM and Fedora systemd runtime checks (C5) | [openvibes-console.md](openvibes-console.md) |
| `console-auth` | console module | opaque session secrets, secure cookie formatting, and browser-origin validation | [console-auth.md](console-auth.md) |
| `console-auth-http` | console module | pre-auth, local login/logout, scoped reads, token/service-account/rule APIs, bearer-read auth, and per-request capabilities (C3) | [console-auth-http.md](console-auth-http.md) |
| `console-triage` | console module | latest-finding analyst workflow, stale-write protection, audit/history, and observation-triggered reopen (C3) | [console-triage.md](console-triage.md) |
| `console-detection` | console module and web panel | original evaluation evidence and observation-scoped historical rule detail (P17) | [console-detection.md](console-detection.md) |
| `console-assistant` | console module and web page | opt-in local model chat with permission-scoped agent and finding lookups, safe citations, and in-tab-only history | [console-assistant.md](console-assistant.md) |
| `console-web` | web application | the embedded console interface: sign-in, inspector panel stack, floating windows, assistant dock, command palette, saved views, dashboards (Number, Graph and more widgets); demo build for the GitHub Pages preview | [console-web.md](console-web.md) |
| `console-hosts` | web pages and console API | the Hosts list (filters with counts, saved views, columns, server paging) and the host page | [console-hosts.md](console-hosts.md) |
| `console-alarms` | web pages | the Alarms list (filters with counts, saved views, columns, server paging, the bulk bar) and an alarm's page | [console-alarms.md](console-alarms.md) |
| `console-vulnerabilities` | web pages, console API and store queries | the Vulnerabilities list, one row per CVE (filters with counts, saved views, columns, server paging, open-only bulk), and a vulnerability's page | [console-vulnerabilities.md](console-vulnerabilities.md) |
| `console-compliance` | web pages, console API and store queries | the Compliance list, one row per check (filters with counts, saved views, columns, server paging, open-only bulk), inferred passing, and a check's page | [console-compliance.md](console-compliance.md) |
| `console-ports` | web pages, console API and store queries | the Ports list, one row per port (filters with counts, saved views, columns, server paging, needs-a-look flags), and a port's page; ports as case items | [console-ports.md](console-ports.md) |
| `console-services` | web pages, console API and store queries | the Services list, one row per unit (filters with counts, saved views, columns, server paging, needs-a-look flags), and a service's page; services as case items | [console-services.md](console-services.md) |
| `console-software` | web pages, console API and store queries | the Software list, one row per package name across managers (filters with counts, saved views, columns, server paging, fix and used-by columns), and a package's page; bare-name software case items | [console-software.md](console-software.md) |
| `change-log` | store module | what appeared and went away on each host, for packages, listening ports and services, written at ingest and pruned after 90 days (schema 65) | [change-log.md](change-log.md) |
| `console-dashboards` | console module | user dashboards: layouts, sharing by role, home (schema 26) | [console-dashboards.md](console-dashboards.md) |
| `console-cases` | console module | investigations: items, notes, assignment, closing with evidence; scope-aware visibility (schema 35) | [console-cases.md](console-cases.md) |
| `count-history` | store module and console endpoint | daily per-host problem counts (schema 44) written by maintenance, served as count history graphs by `/api/v1/metrics/history` | [count-history.md](count-history.md) |
| `console-settings` | console module | typed general settings: list, change, audited | [console-settings.md](console-settings.md) |
| `saved-views` | store module and console API | saved list views and hidden columns per person and page (schema 56) | [saved-views.md](saved-views.md) |
| `console-rbac` | console module | permission resolution, the share check, people and role-holder APIs, and asset-group selector APIs | [console-rbac.md](console-rbac.md) |
| `rule-set-assignment` | store module, console API, distribution and ingest behaviour | per-group switches for the project's assignable rule sets (hardening L1/L2): defaults, overrides, on wins, `410` answers, matches ended when a host stops running a set (schema 49) | [rule-set-assignment.md](rule-set-assignment.md) |
| `console-about` | console module | About page, platform/component versions, newer-release check | [console-about.md](console-about.md) |
| `console-build-stamp` | build-script module | sorted frontend inventories and SHA-256 validation | [console-build-stamp.md](console-build-stamp.md) |

Sizing (measured and estimated requirements): [`../sizing.md`](../sizing.md).
Architecture and design: [`../specs/`](../specs/). Implementation plans:
[`../plans/`](../plans/).
