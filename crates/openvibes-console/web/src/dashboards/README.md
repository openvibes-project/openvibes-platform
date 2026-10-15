# dashboards

The home dashboard: the tile grid, the widget types and the editor. Shown by `DashboardsView.tsx`, registered in app/registry.tsx.

| File | What it does |
|---|---|
| `DashboardsView.tsx` | The Dashboards view: shows the home or chosen dashboard and runs edit mode. |
| `Grid.tsx` | The 12-column tile grid: drag, resize and keyboard in edit mode. |
| `widgets.tsx` | The list of widget types a dashboard can hold, each with its editor and renderer. |
| `tiles.tsx` | The count and list tiles. |
| `charts.tsx` | The trend and graph tiles, and the free-text note tile. |
| `attention.tsx` | The greeting and the "Needs attention" list. |
| `builtin.ts` | The built-in Overview layout (read-only; duplicate it to edit). |
| `editor.ts` | The draft being edited, shared by grid, gallery and settings; saves carry the version. |
| `panels.tsx` | The widget gallery and per-widget settings in the inspector. |
| `settings.tsx` | The widget settings controls. |
| `layout.ts` | Layout rules, the same as the server's, so the editor flags problems before saving. |
| `config.ts` | Reads widget settings from any console version, falling back to defaults. |
| `defaults.ts` | Starting size and settings of each widget type (plain data). |
| `metrics.ts` | The catalogue of counts; must equal the server's catalogue. |
| `history.ts` | Loads the daily history of a count for trend tiles. |
| `legacy.ts` | Maps old (pre compliance-rename) dashboard IDs to the current ones. |
| `CountError.tsx` | What a tile shows when a count is not allowed or fails. |

More: [docs/components/console-dashboards.md](../../../../../docs/components/console-dashboards.md)
