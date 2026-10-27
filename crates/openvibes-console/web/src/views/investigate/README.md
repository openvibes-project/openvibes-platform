# views/investigate

The lists you investigate from. A row opens its panel from `panels/` in the inspector; a host, an alarm, a check, a vulnerability and a case open their pages.

| File | What it does |
|---|---|
| `Hosts.tsx` | The Hosts list (screen 16): server filters with counts, saved views, columns, summary line and paging; routes `/hosts/{id}` and `/hosts/{id}/software\|ports\|services` to `host/`. |
| `host/` | A host's page (screen 17) and its software, ports and services pages; see its README. |
| `Alarms.tsx` | The Alarms list (screen 29): server filters with counts (Host as a chip), saved views, columns, summary line, paging and the bulk bar; routes `/alarms/{id}` to `alarm/`. |
| `alarm/` | An alarm's page (screen 30); see its README. |
| `Findings.tsx` | The Compliance list (screen 27): one row per check over `/api/v1/compliance-list`, server filters, saved views, columns and the bulk bar. A row opens the check's page at `/compliance/{set}/{rule}` (`check/`). |
| `check/` | A check's page (screen 28); see its README. |
| `Vulnerabilities.tsx` | The Vulnerabilities list (screen 25): one row per CVE, server filters with counts (Host and Advisory as chips), saved views, columns, summary line, paging and the bulk bar; routes `/vulnerabilities/{key}` to `vulnerability/`. |
| `vulnerability/` | A vulnerability's page (screen 26); see its README. |
| `Software.tsx` | Packages across the fleet. |
| `Ports.tsx` | Open ports across the fleet. |
| `Services.tsx` | Running services across the fleet (5f rewrites it). |
| `Cases.tsx` | The Cases list (screen 31): one row per case over `/api/v1/case-list`, server filters with counts (Host as a chip), saved views, columns, summary line (ready to close) and paging. A row opens `/cases/{id}`; New case is `/cases/new`; routes both to `case/`. |
| `case/` | A case's page (screen 32) and the new-case form; see its README. |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
