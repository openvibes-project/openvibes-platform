# panels/hosts

The panels about hosts: comparing two, and something found across hosts (package, port, service). A host itself is a page (`views/investigate/host/`). Each is registered as a panel kind in app/registry.tsx.

| File | What it does |
|---|---|
| `ComparePanel.tsx` | Two hosts side by side, showing only what differs. |
| `compare.ts` | Logic for ComparePanel.tsx: the difference between two lists, unit-tested. |
| `PackagePanel.tsx` | One package across the fleet: versions and hosts. |
| `PortPanel.tsx` | One port or service unit across the fleet and the hosts that have it. |
| `MoreHosts.tsx` | The "Show more" paging for a panel's host list. |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
