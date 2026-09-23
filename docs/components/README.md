# Platform Components

One page per crate or service: purpose, interfaces, configuration, failure
behaviour, and how to test. Updated in the same change as the component.

| Component | Kind | Status | Page |
|---|---|---|---|
| `platform-config` | library | built (PM0) | [platform-config.md](platform-config.md) |
| `platform-pki` | library | CA hierarchy, CSR checks, client certificates (PM2) | [platform-pki.md](platform-pki.md) |
| `platform-store` | library | schema 3, partitions, status, tokens, agents, CA certificates (PM1, PM2) | [platform-store.md](platform-store.md) |
| `openvibes-admin` | CLI | migrate, status, maintenance (PM1); ca, token, agent (PM2) | [openvibes-admin.md](openvibes-admin.md) |
| `openvibes-ingest` | service, port 18423 | enroll, renew, heartbeat, findings, limits, health (PM3) | [openvibes-ingest.md](openvibes-ingest.md) |
| `integration-agent` | test script | real agent against ingest: enroll, deliver exactly once, restart, renew, revoke, re-enroll (PM4) | [integration-agent.md](integration-agent.md) |
| `packaging` | RPMs | openvibes-ingest, openvibes-admin, hardened units, maintenance timer (PM4) | [packaging.md](packaging.md) |
| `load` | test tool | openvibes-load generator and runner (PM5) | [load.md](load.md) |

Architecture and design: [`../specs/`](../specs/). Implementation plans:
[`../plans/`](../plans/).
