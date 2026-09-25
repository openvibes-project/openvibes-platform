# Platform Components

One page per crate or service: purpose, interfaces, configuration, failure
behaviour, and how to test. Updated in the same change as the component.

| Component | Kind | Status | Page |
|---|---|---|---|
| `platform-config` | library | built (PM0) | [platform-config.md](platform-config.md) |
| `platform-pki` | library | CA hierarchy, CSR checks, client certificates (PM2) | [platform-pki.md](platform-pki.md) |
| `platform-store` | library | schema 18, OSV packages, vulnerability data/enrichment, rule distribution, console identity/sessions, triage, partitions, status, tokens, agents, CA certificates (PM1, PM2, VM0–VM5, OSV D2–D3, C2, C3) | [platform-store.md](platform-store.md) |
| `platform_store::console_auth` | module | local identity/session store, access inventory, asset-group/tag changes, enrollment tokens, and service-account bearer tokens (C3) | [console-auth-store.md](console-auth-store.md) |
| `platform_store::console_read` | module | bounded, cursor-paginated console read models and SQL-enforced scoped agent reads (C2/C3) | [console-read.md](console-read.md) |
| `platform_store::audit` | module | audit event reads/writes, versioned retention policy, and bounded expiry cleanup (C3) | [console-audit.md](console-audit.md) |
| `platform-agent-server` | library | shared agent-facing server: TLS, auth, limits, logs, health, drain (SP2 DM0) | [platform-agent-server.md](platform-agent-server.md) |
| `openvibes-admin` | CLI | migrate, status, maintenance (PM1); ca, token, agent (PM2); rules (SP2); local console user bootstrap and administration (C3) | [openvibes-admin.md](openvibes-admin.md) |
| `openvibes-ingest` | service, port 18423 | enroll, renew, heartbeat, findings, limits, health (PM3) | [openvibes-ingest.md](openvibes-ingest.md) |
| `integration-agent` | test script | real agent against ingest: enroll, deliver exactly once, restart, renew, revoke, re-enroll (PM4); against distribution: poll, update, outage, refused bundle, revoke (SP2) | [integration-agent.md](integration-agent.md) |
| `openvibes-vulns` | service (health 18483) and library | Fedora advisories fetched and verified hourly, exact RPM version matching, vulnerability lifecycle (VM2) | [openvibes-vulns.md](openvibes-vulns.md) |
| `packaging` | RPMs | ingest, distribution, vulns, admin, agent, and console packages; offline console frontend cache pin, hardened units, maintenance timer; whole platform under systemd (PM4, SP2, M6a, VM3, C5) | [packaging.md](packaging.md) |
| `load` | test tool | openvibes-load generator and runner: ingest (PM5), distribution mode (SP2) | [load.md](load.md) |
| `openvibes-console` | web application and `/api/v1` | C3 auth/control plane; TLS 1.3, trusted loopback/Unix-socket proxy, enforced CSP/HSTS; offline RPM and Fedora systemd runtime checks (C5) | [openvibes-console.md](openvibes-console.md) |
| `console-auth` | console module | opaque session secrets, secure cookie formatting, and browser-origin validation | [console-auth.md](console-auth.md) |
| `console-auth-http` | console module | pre-auth, local login/logout, scoped reads, token/service-account/rule APIs, bearer-read auth, and per-request capabilities (C3) | [console-auth-http.md](console-auth-http.md) |
| `console-triage` | console module | latest-finding analyst workflow, stale-write protection, audit/history, and observation-triggered reopen (C3) | [console-triage.md](console-triage.md) |
| `console-auth-ui` | web module | local login page, session gate, logout, enrollment, service-account, signed rule-bundle, and finding triage workflows (C3) | [console-auth-ui.md](console-auth-ui.md) |
| `console-rbac` | console module | permission resolution and access-control inventory, role-binding, and asset-group selector APIs | [console-rbac.md](console-rbac.md) |
| `console-build-stamp` | build-script module | sorted frontend inventories and SHA-256 validation | [console-build-stamp.md](console-build-stamp.md) |

Sizing (measured and estimated requirements): [`../sizing.md`](../sizing.md).
Architecture and design: [`../specs/`](../specs/). Implementation plans:
[`../plans/`](../plans/).
