# demo

An in-browser implementation of /api/v1 over invented data, for the GitHub Pages preview, development and unit tests. It follows the real routes, JSON and permissions; it is not in an installed console's bundle.

| File | What it does |
|---|---|
| `server.ts` | Builds the demo server and registers every area's routes. |
| `context.ts` | Shared context for the routes: the persona's data, permissions, helpers. |
| `data.ts` | The synthetic fleet, findings and advisories (deterministic, example.test hosts). |
| `personas.ts` | The personas the demo can be viewed as (each signs in as a seeded person). |
| `share.ts` | The server's access rules: roles into capabilities (rbac.rs) and the share check (share.rs). |
| `http.ts` | Helpers the routes share: responses, paging, ranking, browser storage. |
| `history.ts` | Synthetic daily history for the metrics history route. |
| `attack.ts` | A small ATT&CK catalog for the demo. |
| `hostGroups.ts` | Host-group membership as the store decides it (console_host_in_group), the rule checks and the membership sentence. |
| `assignments.ts` | The demo's rule-set assignment API, with real status codes. |
| `cases.ts` | The demo's cases store and its rules. |
| `suppressions.ts` | Alarm suppressions with approval, as the store decides them, kept in browser storage. |
| `caseSeed.ts` | The cases the demo starts with. |
| `dashboards.ts` | The demo's dashboard store, kept in browser storage. |
| `routes/` | One file per API area, registered by server.ts. |

More: [docs/components/console-web.md](../../../../../docs/components/console-web.md)
