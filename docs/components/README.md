# Platform Components

One page per crate or service: purpose, interfaces, configuration, failure
behaviour, and how to test. Updated in the same change as the component.

| Component | Kind | Status | Page |
|---|---|---|---|
| `platform-config` | library | built (PM0) | [platform-config.md](platform-config.md) |
| `platform-store` | library | migrations, partitions, status (PM1) | [platform-store.md](platform-store.md) |
| `openvibes-admin` | CLI | migrate, status, maintenance (PM1) | [openvibes-admin.md](openvibes-admin.md) |
| `openvibes-ingest` | service, port 18423 | skeleton; endpoints in PM3 | [openvibes-ingest.md](openvibes-ingest.md) |

Architecture and design: [`../specs/`](../specs/). Implementation plans:
[`../plans/`](../plans/).
