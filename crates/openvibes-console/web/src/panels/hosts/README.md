# panels/hosts

The panels that open on a host, or on something found across hosts (package, port, service), and what they open in turn. Each is registered as a panel kind in app/registry.tsx.

| File | What it does |
|---|---|
| `AgentPanel.tsx` | The host panel: details, findings, alarms, software, hardening and services. |
| `ComparePanel.tsx` | Two hosts side by side, showing only what differs. |
| `compare.ts` | Logic for ComparePanel.tsx: the difference between two lists, unit-tested. |
| `HostExport.tsx` | Exports chosen sections of one host to CSV. |
| `HostHardening.tsx` | The host's Hardening line: which rule sets run there and why. |
| `HostLabels.tsx` | The "Groups and labels" card: the host's groups and its editable labels. |
| `HostServices.tsx` | One host's open ports and running services. |
| `PackagePanel.tsx` | One package across the fleet: versions and hosts. |
| `PortPanel.tsx` | One port or service unit across the fleet and the hosts that have it. |
| `MoreHosts.tsx` | The "Show more" paging for a panel's host list. |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
