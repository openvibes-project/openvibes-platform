# views

The screens, one per menu item, grouped by menu section. Each is registered as a view in app/registry.tsx and opens panels from `panels/`.

| File | What it does |
|---|---|
| `investigate/` | Lists you look into: hosts, alarms, findings, vulnerabilities, software, ports, cases. |
| `operate/` | Working on rules: coverage, site rules, alarm suppressions. |
| `admin/` | Settings and the audit log. |
| `help/` | The About page. |
| `lists/` | Filter and row definitions shared by list views and dashboard tiles. |

More: [docs/components/console-web.md](../../../../../docs/components/console-web.md)
