# src/assistant

The assistant's tests that need a database or a fake fetch socket; the assistant itself is `../assistant.rs` for now.

| File | What it does |
|---|---|
| `internet_tests.rs` | Internet lookups with a fake fetch socket: permissions, off switch, audit row, hourly limit, dead socket. |
| `lookup_tests.rs` | Every lookup offered to the model, against PostgreSQL, within the user's permissions and scopes. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
