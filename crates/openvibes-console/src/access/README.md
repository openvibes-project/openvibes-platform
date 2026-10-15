# src/access

Who may do what in the console. For now it holds the checks every area's handlers run; sign-in, roles, users and service accounts move here next.

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules. |
| `guard.rs` | Session and permission checks: the caller, their capabilities and scope, and the 401/403/503 answers. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
