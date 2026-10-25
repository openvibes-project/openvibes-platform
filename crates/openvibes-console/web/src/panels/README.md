# panels

The detail panels that open in the inspector beside a list (or in a floating window). Each kind is registered as a panel kind in app/registry.tsx; the folders group them by area.

| File | What it does |
|---|---|
| `hosts/` | Host, package, port and compare panels, and the host export. |
| `alarms/` | An alarm's evidence and the suppress form (an alarm itself is a page, `views/investigate/alarm/`). |
| `triage/` | The triage actions alarms, compliance checks and vulnerabilities share. |
| `cases/` | The add-to-case button, case badges and case logic (a case is a page: `views/investigate/case/`). |
| `rules/` | Rule set and site rule panels, and where a set runs. |
| `admin/` | Panels for users, service accounts, asset groups, tokens and audit. |

More: [docs/components/console-web.md](../../../../../docs/components/console-web.md)
