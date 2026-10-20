# views/lists

Definitions that the list views and the dashboard List tile share, so a tile always matches its view.

| File | What it does |
|---|---|
| `filters.ts` | The filter catalogue per list. |
| `HostChip.tsx` | The host filter's removable chip ("Host: web-01 ×") on Alarms, Compliance and Vulnerabilities. |
| `rows.ts` | What each list shows for a query, with one host's compliance findings as rows. |
| `testRules.ts` | The rules raised on purpose by the test-trigger tool, so they can be told apart. |

More: [docs/components/console-dashboards.md](../../../../../../docs/components/console-dashboards.md)
