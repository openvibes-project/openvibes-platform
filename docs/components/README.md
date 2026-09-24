# Platform Components

One page per crate or service: purpose, interfaces, configuration, failure
behaviour, and how to test. Updated in the same change as the component.

| Component | Kind | Status | Page |
|---|---|---|---|
| `platform-config` | library | built (PM0) | [platform-config.md](platform-config.md) |
| `platform-pki` | library | CA hierarchy, CSR checks, client certificates (PM2) | [platform-pki.md](platform-pki.md) |
| `platform-store` | library | schema 8, rule distribution, console identity/sessions, partitions, status, tokens, agents, CA certificates (PM1, PM2, C2, C3) | [platform-store.md](platform-store.md) |
| `platform_store::console_auth` | module | hash-only local credentials, pre-auth state, sessions, and login throttles (C3) | [console-auth-store.md](console-auth-store.md) |
| `platform_store::console_read` | module | bounded, cursor-paginated console read models and SQL-enforced scoped agent reads (C2/C3) | [console-read.md](console-read.md) |
| `platform_store::audit` | module | audit event reads/writes, versioned retention policy, and bounded expiry cleanup (C3) | [console-audit.md](console-audit.md) |
| `platform-agent-server` | library | shared agent-facing server: TLS, auth, limits, logs, health, drain (SP2 DM0) | [platform-agent-server.md](platform-agent-server.md) |
| `openvibes-admin` | CLI | migrate, status, maintenance (PM1); ca, token, agent (PM2); rules (SP2); local console user bootstrap and administration (C3) | [openvibes-admin.md](openvibes-admin.md) |
| `openvibes-ingest` | service, port 18423 | enroll, renew, heartbeat, findings, limits, health (PM3) | [openvibes-ingest.md](openvibes-ingest.md) |
| `integration-agent` | test script | real agent against ingest: enroll, deliver exactly once, restart, renew, revoke, re-enroll (PM4); against distribution: poll, update, outage, refused bundle, revoke (SP2) | [integration-agent.md](integration-agent.md) |
| `packaging` | RPMs | openvibes-ingest, openvibes-admin (PM4), openvibes-distribution (SP2), hardened units, maintenance timer; the whole system end to end under systemd with the agent RPM (M6a) | [packaging.md](packaging.md) |
| `load` | test tool | openvibes-load generator and runner: ingest (PM5), distribution mode (SP2) | [load.md](load.md) |
| `openvibes-console` | web application and `/api/v1` | seeded C1 read slice; C3 local auth runtime and readiness; request limits; offline build path | [openvibes-console.md](openvibes-console.md) |
| `console-auth` | console module | opaque session secrets, secure cookie formatting, and browser-origin validation | [console-auth.md](console-auth.md) |
| `console-auth-http` | console module | pre-auth, local login/logout, database-backed browser sessions, and per-request capability resolution (C3) | [console-auth-http.md](console-auth-http.md) |
| `console-auth-ui` | web module | local login page, session gate, and logout action (C3) | [console-auth-ui.md](console-auth-ui.md) |
| `console-rbac` | console module | role permission resolution and access-control read API | [console-rbac.md](console-rbac.md) |
| `console-build-stamp` | build-script module | sorted frontend inventories and SHA-256 validation | [console-build-stamp.md](console-build-stamp.md) |

Sizing (measured and estimated requirements): [`../sizing.md`](../sizing.md).
Architecture and design: [`../specs/`](../specs/). Implementation plans:
[`../plans/`](../plans/).
