# demo

An in-browser implementation of /api/v1 over invented data, for the GitHub Pages preview, development and unit tests. It follows the real routes, JSON and permissions; it is not in an installed console's bundle.

| File | What it does |
|---|---|
| `server.ts` | Builds the demo server and registers every area's routes. |
| `context.ts` | Shared context for the routes: the persona's data, permissions, helpers. |
| `data.ts` | The synthetic fleet, findings and advisories (deterministic, example.test hosts). |
| `personas.ts` | The built-in roles the demo can be viewed as. |
| `http.ts` | Helpers the routes share: responses, paging, ranking, browser storage. |
| `history.ts` | Synthetic daily history for the metrics history route. |
| `attack.ts` | A small ATT&CK catalog for the demo. |
| `assignments.ts` | The demo's rule-set assignment API, with real status codes. |
| `cases.ts` | The demo's cases store and its rules. |
| `caseSeed.ts` | The cases the demo starts with. |
| `dashboards.ts` | The demo's dashboard store, kept in browser storage. |
| `routes/` | One file per API area, registered by server.ts. |

More: [docs/components/console-web.md](../../../../../docs/components/console-web.md)
