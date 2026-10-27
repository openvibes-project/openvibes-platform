# panels/hosts

The panels about hosts: comparing two. A host itself is a page (`views/investigate/host/`). Each is registered as a panel kind in app/registry.tsx.

| File | What it does |
|---|---|
| `ComparePanel.tsx` | Two hosts side by side, showing only what differs. |
| `compare.ts` | Logic for ComparePanel.tsx: the difference between two lists, unit-tested. |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
