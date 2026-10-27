# demo/routes

The demo API's routes, one file per area of /api/v1. Each registers its routes on the demo server in demo/server.ts and mirrors the real console route of the same area.

| File | What it does |
|---|---|
| `access.ts` | People (list, page, create, edit, disable, enable, reset, roles) and service accounts, inside the share. |
| `alarmList.ts` | The Alarms list (`GET /api/v1/alarm-list`): filters, counts with the others applied, the open-alarms summary, sort and paging inside the persona's reach. |
| `alarmSummary.ts` | An alarm's page (`GET /api/v1/alarms/{id}/summary`): the alarm in reach, its siblings as commands seen, the last 24 hours (each sibling's count at the hour it was last seen), the Related card and the `can` flags. |
| `alarms.ts` | Threat alarms, their triage and suppressions. |
| `assets.ts` | Packages, open ports, running services and software across the fleet; `hostServices` is one host's report. |
| `assistant.ts` | The assistant's answers. |
| `cases.ts` | Cases and their items, notes and timeline. |
| `caseList.ts` | The Cases list (`GET /api/v1/case-list`): one row per case the persona sees, filters, counts with the others applied, the summary line, sort and paging. |
| `caseSummary.ts` | A case's page (`GET /api/v1/cases/{id}/summary`): tiles, hosts with their problems per readable kind, who can see it, the can flags. |
| `dashboards.ts` | Dashboards and each user's home dashboard. |
| `findings.ts` | Compliance findings: groups by rule, host matches, history and triage. |
| `groups.ts` | Host groups: list, page, hosts, preview, create, edit and delete, with the server's refusals. |
| `hostList.ts` | The Hosts list (`GET /api/v1/hosts`): filters, per-value counts, summary, sort and paging inside the persona's reach. |
| `hosts.ts` | Hosts (agents), their labels and enrolling new ones. |
| `hostSummary.ts` | A host's page summary (`GET /api/v1/hosts/{id}/summary`): each section and action only where its permission reaches the host. |
| `lists.ts` | Each person's saved views and hidden columns per list page, kept in the browser and checked on load. |
| `metrics.ts` | Counts, their history and the ranked-hosts list. |
| `roles.ts` | The permission catalogue, templates and roles (create, edit, delete). |
| `rules.ts` | Rule sets, bundles, site rule drafts, ATT&CK coverage and per-host rule sets. |
| `session.ts` | The session, password changes and the About page. |
| `settings.ts` | The general settings, the audit log, its retention and the assistant's internet access. |
| `triage.ts` | Bulk triage of alarms, findings and vulnerabilities (an advisory-wide vulnerability item changes only open pairs with a fix, as bulk_triage.rs). |
| `cveFacts.ts` | A CVE's own exploited flag, KEV due date, CVSS and EPSS (cve_enrichment), for the list rows and the page. |
| `checkList.ts` | The Compliance list (`GET /api/v1/compliance-list`): one row per check, failing hosts and inferred passing ones, filters, counts with the others applied, the summary, sort and paging inside the persona's reach; its seed data is `../checkSeed.ts`. |
| `portList.ts` | The Ports list (`GET /api/v1/port-list`): one row per port over the hosts in reach, a host counted once, filters, counts with the others applied, Needs a look, this week's changes, the summary, sort and paging; its data is `../portData.ts`. |
| `portPage.ts` | A port's page (`GET /api/v1/ports/{protocol}/{port}/summary` and `/hosts`): header, tiles, details, By group, recent changes, the Related card by permission, the actions, and the Hosts table with its segments; data from `../portData.ts`. |
| `serviceList.ts` | The Services list (`GET /api/v1/service-list`): one row per unit over the hosts in reach, a host counted once, filters, counts with the others applied, Needs a look, this week's changes, the summary, sort and paging; its data is `../serviceData.ts`. |
| `servicePage.ts` | A service's page (`GET /api/v1/services/{unit}/summary` and `/hosts`): header, tiles, details, ports, By group, recent changes, the Related card by permission, the actions, and the Hosts table with its segments; data from `../serviceData.ts`. |
| `checkSummary.ts` | A check's page (`GET /api/v1/compliance/checks/{set}/{rule}/summary` and `/hosts`): the list's pairs for one check, the 14 days, episodes and publishes as History, Related, the Hosts segments with evidence (masked inputs carry no value), 404 out of reach. |
| `vulnList.ts` | The Vulnerabilities list (`GET /api/v1/vulnerability-list`): one row per CVE, filters, counts with the others applied, the summary, sort and paging inside the persona's reach; lower-confidence matches (below 80) only under the `lowconf` signal. |
| `vulnSummary.ts` | A vulnerability's page (`GET /api/v1/vulnerabilities/{key}/summary` and `/{key}/hosts`): the key resolved (one CVE, a CVE-less advisory, 409 for an advisory with several CVEs), its pairs in reach, what to do per distribution, the Related card, the `can` flags and the Hosts table's segments and paging. No triage history in the demo. |
| `vulnerabilities.ts` | The vulnerability list, summary and one advisory's hosts. |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
