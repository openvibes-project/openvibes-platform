# demo/routes

The demo API's routes, one file per area of /api/v1. Each registers its routes on the demo server in demo/server.ts and mirrors the real console route of the same area.

| File | What it does |
|---|---|
| `access.ts` | Users, role bindings, asset groups and service accounts. |
| `alarms.ts` | Threat alarms, their triage and suppressions. |
| `assets.ts` | Packages, open ports, running services and software across the fleet. |
| `assistant.ts` | The assistant's answers. |
| `cases.ts` | Cases and their items, notes and timeline. |
| `dashboards.ts` | Dashboards and each user's home dashboard. |
| `findings.ts` | Compliance findings: groups by rule, host matches, history and triage. |
| `hosts.ts` | Hosts (agents), their tags and enrolling new ones. |
| `metrics.ts` | Counts, their history and the ranked-hosts list. |
| `rules.ts` | Rule sets, bundles, site rule drafts, ATT&CK coverage and per-host rule sets. |
| `session.ts` | The session, password changes and the About page. |
| `settings.ts` | The audit log, its retention and the assistant's internet access. |
| `triage.ts` | Bulk triage of alarms, findings and vulnerabilities. |
| `vulnerabilities.ts` | The vulnerability list, summary and one advisory's hosts. |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
