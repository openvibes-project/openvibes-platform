# ui

Shared building blocks used by views, panels and dashboards. They know nothing about alarms or hosts; a `.ts` file here is the testable logic behind the `.tsx` of a similar name.

| File | What it does |
|---|---|
| `DataTable.tsx` | The one table every view uses: sort, keyboard, selection, open-in-inspector. |
| `table.ts` | Logic for DataTable.tsx: stable sort and text filter. |
| `selection.ts` | Row selection for bulk actions: ranges, all on screen, all matching. |
| `ViewHeader.tsx` | Header of a list view: title, count, text filter, quick filters, saved views (in the browser; pages move to `list/`). |
| `list/` | A list page's FilterBar, columns menu, summary line and saved views kept by the console. |
| `detail/` | The detail page layout and its tiles. |
| `bits.tsx` | Small pieces: badges, object links, loading, empty and error states. |
| `panel.tsx` | Panel layout pieces: sections, tabs, inline confirm. |
| `Select.tsx` | The console's own dropdown (never the browser's native one). |
| `select.ts` | Logic for Select.tsx and Menu.tsx: grouping, filtering, stepping, placement, whether the button is on screen. |
| `Segmented.tsx` | A button row for two to four choices. |
| `segmented.ts` | Logic for Segmented.tsx: arrow-key stepping and extra option. |
| `Menu.tsx` | A button that opens a short list of actions. |
| `Switch.tsx` | An on/off row. |
| `Field.tsx` | A labelled Select. |
| `Icon.tsx` | The inline stroke icon set. |
| `LineChart.tsx` | A line chart drawn at pixel size. |
| `linechart.ts` | Logic for LineChart.tsx: paths, gaps and ticks. |
| `trend.tsx` | A small bar chart of hosts reporting per day. |
| `toast.tsx` | Short messages that appear and fade. |
| `format.ts` | Formatting for times, counts and plurals. |
| `auditActions.ts` | Audit action ids as short sentences ("Gave a role"), with a readable fallback. |
| `csv.ts` | Safe CSV cells and the download for the CSV exports. |

More: [docs/components/console-web.md](../../../../../docs/components/console-web.md)
