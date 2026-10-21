# ui/list

The shared pieces of a list page (roles spec §10.3, approved screen 16). Each list page supplies only its filters, columns and summary; Hosts is the first user.

| File | What it does |
|---|---|
| `FilterBar.tsx` | Search (`q`, "/" focuses it), a chip per filter listing its values with counts, a chosen value as a chip with ×, saved views, Clear all, Save view and Columns. |
| `filters.ts` | The `ListFilter` type and the URL helpers: chosen chips, Clear all (keeps `sort` and `dir`), a view's query and applying one, `PAGE` (`offset`: not a filter, not saved). |
| `ColumnsMenu.tsx` | The Columns menu: a checkbox per column, Host always shown, each change saved at once. |
| `SummaryLine.tsx` | "9 online · 4 with an older agent": parts joined with " · ", zero parts skipped when asked; a live region. |
| `savedViews.ts` | `useSavedViews(page)`, `useHiddenColumns(page)`, saving and deleting, `columnSaver` (column toggles in order), and `importBrowserViews` for views kept in the browser before. |

More: [docs/components/console-web.md](../../../../../../docs/components/console-web.md)
