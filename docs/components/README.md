# Platform Components

One page per crate or service: purpose, interfaces, configuration, failure
behaviour, and how to test. Updated in the same change as the component.

| Component | Kind | Status | Page |
|---|---|---|---|
| `platform-config` | library | built (PM0) | [platform-config.md](platform-config.md) |
| `platform-pki` | library | CA hierarchy, CSR checks, client certificates (PM2) | [platform-pki.md](platform-pki.md) |
| `platform-store` | library | schema 6, rule distribution, partitions, status, tokens, agents, CA certificates (PM1, PM2) | [platform-store.md](platform-store.md) |
| `platform-agent-server` | library | shared agent-facing server: TLS, auth, limits, logs, health, drain (SP2 DM0) | [platform-agent-server.md](platform-agent-server.md) |
| `openvibes-admin` | CLI | migrate, status, maintenance (PM1); ca, token, agent (PM2); rules (SP2) | [openvibes-admin.md](openvibes-admin.md) |
| `openvibes-ingest` | service, port 18423 | enroll, renew, heartbeat, findings, limits, health (PM3) | [openvibes-ingest.md](openvibes-ingest.md) |
| `openvibes-distribution` | service, port 18424 | `POST /v1/rule-bundle`: signed bundles to agents (SP2 DM2) | [openvibes-distribution.md](openvibes-distribution.md) |
| `load` | test tool | openvibes-load generator and runner: ingest (PM5), distribution mode (SP2) | [load.md](load.md) |
| `openvibes-console` | web application and `/api/v1` | C0 build/browser contracts implemented; offline package build and final brand assets remain | [openvibes-console.md](openvibes-console.md) |
| `integration-agent` | test script | real agent against ingest: enroll, deliver exactly once, restart, renew, revoke, re-enroll (PM4) | [integration-agent.md](integration-agent.md) |
| `packaging` | RPMs | openvibes-ingest, openvibes-admin, hardened units, maintenance timer (PM4) | [packaging.md](packaging.md) |

Sizing (measured and estimated requirements): [`../sizing.md`](../sizing.md).
Architecture and design: [`../specs/`](../specs/). Implementation plans:
[`../plans/`](../plans/).
