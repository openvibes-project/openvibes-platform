# src/assistant

The assistant: the chat endpoints, its runtime and the lookups it may run within the asker's permissions, and the administrator's switch for internet lookups.

| File | What it does |
|---|---|
| `mod.rs` | The module list, the names other areas use, and `routes()`: the paths this area serves. |
| `chat.rs` | The status and message endpoints. |
| `runtime.rs` | The runtime: backend probe, request capacity per user, and the leased chat backend. |
| `lookups.rs` | Runs each lookup offered to the model within the user's console permissions. |
| `types.rs` | Request and response types of the chat endpoints. |
| `internet.rs` | The administrator's switch for internet lookups: read, update, test connection. |
| `fetch_client.rs` | Internet lookups through `openvibes-fetch`: one socket request per lookup, per-user rate limit, audit row, fixed failure notes. |
| `internet_types.rs` | Request and response types of the internet setting. |
| `internet_tests.rs` | Internet lookups with a fake fetch socket: permissions, off switch, audit row, hourly limit, dead socket. |
| `stored.rs` | The assistant's settings from the console put over `[assistant]` of the configuration file at start; invalid settings leave the assistant off. |
| `stored_tests.rs` | That overlay: the stored value wins, the file keeps the rest, settings alone can turn it on, a restriction is never undone by a looser file. |
| `lookup_tests.rs` | Every lookup offered to the model, against PostgreSQL, within the user's permissions and scopes. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
