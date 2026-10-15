# panels

The detail panels that open in the inspector beside a list (or in a floating window). Each kind is registered as a panel kind in app/registry.tsx; the folders group them by area.

| File | What it does |
|---|---|
| `hosts/` | Host, package, port and compare panels, and the host export. |
| `alarms/` | The threat alarm panel and its evidence. |
| `findings/` | The compliance finding and vulnerability advisory panels. |
| `triage/` | The triage actions and the detail template alarms, findings and advisories share. |
| `cases/` | The case panel and the add-to-case button. |
| `rules/` | Rule set and site rule panels, and where a set runs. |
| `admin/` | Panels for users, service accounts, asset groups, tokens and audit. |

More: [docs/components/console-web.md](../../../../../docs/components/console-web.md)
