# demo

An in-browser implementation of /api/v1 over invented data, for the GitHub Pages preview, development and unit tests. It follows the real routes, JSON and permissions; it is not in an installed console's bundle.

| File | What it does |
|---|---|
| `server.ts` | Builds the demo server and registers every area's routes. |
| `context.ts` | Shared context for the routes: the persona's data, permissions, helpers. |
| `data.ts` | The synthetic fleet, findings and advisories (deterministic, example.test hosts). |
| `checkSeed.ts` | Hand-made compliance checks for the Compliance list (hardening and site rule sets, a check in every area, every triage state, an ended finding, an expired acceptance, a check only passing). |
| `portNames.ts` | The fixed map of well-known ports (name, usual use, class, area, packages), as `port_names.rs` holds it. |
| `portData.ts` | What the Ports list and a port's page read: each reachable host's listeners from its role, and the last week of the demo's listener change log. |
| `serviceNames.ts` | The fixed map of well-known services (name, usual use, class, area, packages), as `service_names.rs` holds it. |
| `softwareData.ts` | What the Software list and a package's page read: each reachable host's packages, the open advisories that name them, the services that run from them, and the demo's package change log. |
| `serviceData.ts` | What the Services list and a service's page read: each reachable host's units from its role, the packages that match them by name, and the last weeks of the demo's service change log. |
| `vulnSeed.ts` | Hand-made vulnerabilities for the cases the Vulnerabilities list and page must show (shared CVEs, due dates, assignees, a fixed pair, a lower-confidence match). |
| `listQuery.ts` | Shared query validation for the list routes (`listQueryError`). |
| `personas.ts` | The personas the demo can be viewed as (each signs in as a seeded person). |
| `share.ts` | The server's access rules: roles into capabilities (rbac.rs) and the share check (share.rs). |
| `http.ts` | Helpers the routes share: responses, paging, ranking, browser storage. |
| `history.ts` | Synthetic daily history for the metrics history route. |
| `attack.ts` | A small ATT&CK catalog for the demo. |
| `hostGroups.ts` | Host-group membership as the store decides it (console_host_in_group), the rule checks and the membership sentence. |
| `versionOrder.ts` | Agent version order, the twin of the store's version_order.rs (same table test). |
| `assignments.ts` | The demo's rule-set assignment API, with real status codes. |
| `cases.ts` | The demo's cases store and its rules. |
| `caseRules.ts` | The cases' checks that need no state: problem answers and messages, titles, notes, ids, outcomes and the closing note. |
| `caseReopen.ts` | The cases' lazy reopen checks: run-out accepted risk (the case's before step 5d, each item's since) and returned evidence. |
| `suppressions.ts` | Alarm suppressions with approval, as the store decides them, kept in browser storage. |
| `caseSeed.ts` | The cases the demo starts with: every outcome, an empty case, a software-only one, one with an item the pilot lead cannot see, a run-out acceptance and a quiet case. |
| `dashboards.ts` | The demo's dashboard store, kept in browser storage. |
| `routes/` | One file per API area, registered by server.ts. |

More: [docs/components/console-web.md](../../../../../docs/components/console-web.md)
