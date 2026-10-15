# src/cases

Cases in the console: where one investigation happens (design in `docs/specs/2026-10-04-console-cases-design.md`).

| File | What it does |
|---|---|
| `mod.rs` | The folder's modules, the public names of its types, and `routes()`: the paths this area serves. |
| `list.rs` | The case list, open, one case and update. |
| `items.rs` | Notes, items and item outcomes of a case, and the cases holding an item. |
| `lookups.rs` | Items in open cases (list badges) and the users a case can be assigned to. |
| `types.rs` | Request and response types, and the query parameters. |
| `views.rs` | Store rows turned into response views. |
| `answers.rs` | JSON answers, refusals and problem responses, with the messages for validation codes. |
| `permissions.rs` | Who may read or change cases: session, permission and agent scope. |
| `request.rs` | Reading a request: cursors, titles, notes, times and `If-Match`. |

More: [docs/components/openvibes-console.md](../../../../docs/components/openvibes-console.md)
