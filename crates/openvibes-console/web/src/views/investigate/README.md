# views/investigate

The lists you investigate from. A row opens its panel from `panels/` in the inspector.

| File | What it does |
|---|---|
| `Hosts.tsx` | The Hosts list (screen 16): server filters with counts, saved views, columns, summary line and paging; `/hosts/{id}` shows the host's panel full width until its page is built. |
| `Alarms.tsx` | Threat alarms, newest first. |
| `Findings.tsx` | Compliance findings by rule. |
| `Vulnerabilities.tsx` | Vulnerabilities by advisory. |
| `Software.tsx` | Packages across the fleet. |
| `Ports.tsx` | Open ports and running services across the fleet. |
| `Cases.tsx` | Cases: the list of investigations. |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
