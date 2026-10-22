# views/investigate

The lists you investigate from. A row opens its panel from `panels/` in the inspector; a host and an alarm open their pages.

| File | What it does |
|---|---|
| `Hosts.tsx` | The Hosts list (screen 16): server filters with counts, saved views, columns, summary line and paging; routes `/hosts/{id}` and `/hosts/{id}/software\|ports\|services` to `host/`. |
| `host/` | A host's page (screen 17) and its software, ports and services pages; see its README. |
| `Alarms.tsx` | The Alarms list (screen 29): server filters with counts (Host as a chip), saved views, columns, summary line, paging and the bulk bar; routes `/alarms/{id}` to `alarm/`. |
| `alarm/` | An alarm's page (screen 30); see its README. |
| `Findings.tsx` | Compliance findings by rule; `host=` lists one host's current findings. |
| `Vulnerabilities.tsx` | The Vulnerabilities list (screen 25): one row per CVE, server filters with counts (Host and Advisory as chips), saved views, columns, summary line, paging and the bulk bar; `/vulnerabilities/{key}` is a stand-in until the CVE's page. |
| `Software.tsx` | Packages across the fleet. |
| `Ports.tsx` | Open ports and running services across the fleet. |
| `Cases.tsx` | Cases: the list of investigations. |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
