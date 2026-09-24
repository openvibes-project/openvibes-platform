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
| `integration-agent` | test script | real agent against ingest: enroll, deliver exactly once, restart, renew, revoke, re-enroll (PM4); against distribution: poll, update, outage, refused bundle, revoke (SP2) | [integration-agent.md](integration-agent.md) |
| `packaging` | RPMs | openvibes-ingest, openvibes-admin (PM4), openvibes-distribution (SP2), hardened units, maintenance timer | [packaging.md](packaging.md) |
| `load` | test tool | openvibes-load generator and runner: ingest (PM5), distribution mode (SP2) | [load.md](load.md) |
| `openvibes-console` | web application and `/api/v1` | seeded C1 read slice; request limits; offline build path | [openvibes-console.md](openvibes-console.md) |
| `console-auth` | console module | opaque session-secret generation and secure cookie formatting | [console-auth.md](console-auth.md) |
| `console-build-stamp` | build-script module | sorted frontend inventories and SHA-256 validation | [console-build-stamp.md](console-build-stamp.md) |

Sizing (measured and estimated requirements): [`../sizing.md`](../sizing.md).
Architecture and design: [`../specs/`](../specs/). Implementation plans:
[`../plans/`](../plans/).
