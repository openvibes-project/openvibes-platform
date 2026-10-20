# views/investigate/host

A host's page (approved screen 17; roles spec §10.2) and its lists. It replaces the old host panel and its tabs, keeping everything they showed.

| File | What it does |
|---|---|
| `HostPage.tsx` | The page at `/hosts/{id}`: header facts and actions (Compare, Export, Add to case, Ask about this, ⋯ Revoke… with a reason), four tiles to the filtered lists, and the cards; reads the summary route and the agent's record. |
| `HostCards.tsx` | Details, Protection (threat alarms, hardening, last test), Rule sets, Certificates; the top three open alarms, failing checks and vulnerabilities with "Show all n"; the software, ports and services summary. |
| `HostSubPage.tsx` | `/hosts/{id}/software\|ports\|services` at full width, and the host's software list. |
| `HostLabels.tsx` | The "Groups and labels" card: the host's groups and its editable labels. |
| `HostHardening.tsx` | The Hardening row: which rule sets run there and why. |
| `HostServices.tsx` | One host's open ports and running services. |
| `HostExport.tsx` | Exports chosen sections of one host to CSV. |

More: [docs/components/console-web.md](../../../../../../../docs/components/console-web.md)
