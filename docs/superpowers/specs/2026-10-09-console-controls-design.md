# Console controls: no browser-drawn controls, editors that speak plainly — design

Date: 2026-10-09. Status: approved in a design session with mockups
(`.superpowers/brainstorm/1578878-1791542463/content/` in the workspace:
`dropdowns.html` option C, `editor-rows.html` options 2 and 4 plus the Graph
editor, `tiles-page.html` options A, C and D). Must land before v0.2.6.

## 1. Why

The user found unstyled parts while creating a graph on a new dashboard. An audit
of the dashboard page found these:

- **Native dropdowns:** 10 `<select>`s in the widget editors open the browser's own
  list, with a pink highlight and system font. The console has 18 more.
- **Graph editor:** count dropdowns are narrower than the other fields, the
  "Remove" buttons are unstyled and misaligned, and "+ Add count" looks like a
  text box.
- **Needs attention:** browser-default checkboxes.
- **Number inputs:** browser spinners.
- **Panel header:** shows internal ids (`graph-1`).
- **List editor:** shows raw view names (`compliance`) and makes you type a query
  string (`severity=critical`). The Trend editor makes you type `rule set/rule`.
- **Edit icon:** both the page and the tiles use a filter funnel for "Edit".
- **Add widget icons:** shared or wrong icons. Number, Trend and Graph look the
  same, List is a shield and Note is a question mark.
- **New widgets:** stack in one narrow column.
- **Severity badge case:** differs between tiles ("critical" and "Critical").

Design principle (decisions.md): the interface comes first. Success means:

- no browser-drawn control anywhere in the console;
- every editor row aligned;
- no internal id or query syntax shown to the user.

## 2. Shared controls (`src/ui/`)

### 2.1 Select

The console's dropdown. It generalises `Picker` (`src/ui/Picker.tsx`), whose own
comment says why: the browser draws the native popup, so it cannot be themed.

- **API:**
  `Select<T extends string>({ label, value, onChange, options, placeholder? })`.
  `options` is either `{ value, label }[]` or groups
  `{ group: string; options: { value, label }[] }[]`.
- **Closed:** looks like today's `.select` field (surface-2, line-strong border,
  chevron icon from the icon set).
- **Open:** a surface popup with an 8 px radius and a shadow.
  - The active option uses `--accent-soft`.
  - The chosen option is bold with an accent tick.
  - Group headings are small caps in `--text-3`.
- **Search:** a search box at the top when there are more than 8 options. It
  filters within the groups and hides empty groups. "No match" is shown when
  nothing matches.
- **Keyboard:**
  - ↑/↓ moves through the options, skipping headings.
  - Enter picks the active option.
  - Esc closes the popup and gives focus back to the button.
  - Typing on the closed button opens the popup and searches.
  - Tab closes the popup.
- **Accessibility:** `role="combobox"` on the button, `aria-expanded` and
  `aria-controls`, a `listbox` with `option` and `aria-selected`, and the group
  label as a `role="group"` `aria-label`.
- **Placement:** the popup opens below the button, or above it when there is no
  room. It is the button's width and at most 300 px tall, and scrolls past that.
  It stays inside the inspector, which matters at 390 px wide.
- **`Picker`:** becomes a thin wrapper over `Select`, or its callers move to
  `Select`. Only one popup implementation remains.

### 2.2 Button row (`Segmented`)

For a choice of 2 to 4 options.

- **API:** `Segmented<T>({ label, value, onChange, options })`, using
  `role="radiogroup"` and `role="radio"` with `aria-checked`. Arrow keys move the
  selection.
- **Look:** as in the mockup. A surface-2 track, the chosen option `--accent-soft`
  with an accent inset ring, and equal widths. At phone width the labels stay on
  one line (short labels: "7 d", "30 d", "90 d", "1 y").

### 2.3 Switch

For on/off settings.

- **API:** `Switch({ label, checked, onChange })`, using `role="switch"` and
  `aria-checked`. The whole row is clickable, with the label on the left and the
  switch on the right.
- **Look:** a 30 × 17 track. When on, it is `--accent` with a dark knob.

### 2.4 Rule

No native `<select>` and no unstyled `<input type="checkbox|radio|number">` stays
in `src/`. A unit test scans `src/**/*.tsx` and fails on `<select` and on those
input types. There is one documented exception list, which starts empty.

## 3. Widget editors

- **Header:** the panel header says "Edit widget · <type label>", for example
  "Edit widget · Graph", never the widget id.
- **Graph:**
  - **Counts:** a "Counts" label with a quiet "up to 4" on the right.
  - **Each count row:** the line's series colour dot (`--series-n`), a full-width
    `Select` grouped as All kinds, Alarms, Vulnerabilities, Compliance and Hosts
    (the catalogue's kinds), and a quiet 32 px ✕ icon button labelled
    "Remove count N".
  - **Adding:** "＋ Add a count" is an accent text button, hidden at 4 counts.
  - **Options:** already chosen counts stay disabled, as today.
  - **Period:** `Segmented` 7 d · 30 d · 90 d · 1 y.
  - **Line:** `Segmented` Smooth · Stepped.
- **Number:**
  - **Count:** a grouped `Select`.
  - **Trend:** `Segmented` Off · 7 d · 30 d · 90 d.
- **Breakdown:** "Break down" is a `Segmented` (4
  options: Alarms, Vulnerabilities, Compliance, Hosts).
- **Needs attention:**
  - **Kinds:** one `Switch` per kind.
  - **Show at most:** `Segmented` 5 · 8 · 10 · 15.
  - **Stored values:** a value outside these options that is already stored is
    shown as a fifth, selected option until it is changed.
- **Most exposed hosts:**
  - **Count:** `Segmented` All kinds · Vulnerabilities only.
  - **Hosts:** `Segmented` 3 · 6 · 10, with the same rule for a stored value.
- **List:**
  - **List:** a `Select` with proper names: Compliance findings, Vulnerabilities,
    Hosts, Audit log.
  - **Filters:** chips in words, such as "Severity: critical ✕" and "Known
    exploited ✕".
  - **"＋ Add filter":** a small menu of the filters the chosen list supports. A
    filter with values (Severity) opens its values; a flag (Known exploited) adds
    directly.
  - **Changing the list:** removes the filters the new list does not support.
  - **Rows:** `Segmented` 5 · 8 · 10 · 15.
  - **Storage:** unchanged. The config keeps `query` as today, so stored
    dashboards keep working. The chips are a view of `query`. Unknown parameters
    in an old `query` show as a plain chip ("bad=1 ✕") so they can be removed,
    and they are never dropped silently.
  - **Change from mockup D:** the filters are chosen in the editor, not in the
    list view, so a dashboard being edited is never left.
- **Trend:**
  - **Compliance rule:** a searchable `Select` of the compliance rules the user
    can see, shown as "<title> (rule set)". The value stays `set/rule`. A stored
    rule that no longer exists shows as "<set/rule> (not found)".
  - **Days:** `Segmented` 7 · 14 · 30.
- **Note:** unchanged apart from the header.
- **Remove widget:** stays the existing danger button.

### 3.1 One filter catalogue per list

The list views define their filter chips inline today, for example
`views/Vulnerabilities.tsx` has `{ label: "Known exploited", param: "exploited",
value: "true" }`. These move to `src/views/filters.ts`, keyed by `ListView`:

```ts
export type FilterDef = { param: string; label: string; values?: { value: string; label: string }[]; flag?: string };
export const LIST_FILTERS: Record<ListView, FilterDef[]>;
```

The list views build their chip bars from it, keeping their counts. The List
editor builds its chips and its "＋ Add filter" menu from it. One source means the
editor can only offer filters the list understands. Values that the views compute
at runtime, such as the compliance rule sets, are offered when the data is loaded.
Until then they are left out.

## 4. Tiles and page

- **Edit:** a pencil icon, both on the page "Edit" button and on each tile in edit
  mode. A pencil is added to the icon set if it is missing.
- **Add widget icons**, one per type:

  | Widget | Icon |
  |---|---|
  | Number | a hash or "123" |
  | Breakdown | a stacked bar |
  | Needs attention | an alert |
  | List | rows |
  | Trend | bars |
  | Most exposed hosts | a server |
  | Graph | a line chart |
  | Note | a note or pencil-on-paper (not the edit pencil) |

  They come from the console's icon set, extended with clean SVGs in its style
  where it lacks one.
- **New widgets:** go to the first free spot, scanning top to bottom and left to
  right, where the widget's default size fits in the 12-column grid. Today they
  stack in a column. This is a pure layout function with a unit test.
- **Severity badges:** use one capitalised label everywhere ("Critical"). The
  List tile's lowercase badge uses the shared `SeverityBadge`.

## 5. The rest of the console

The 18 native `<select>`s in the case, alarm, finding, site rule, admin and alarms
views move to `Select`. Choices of 2 to 4 options become `Segmented` where the
mockup's rule fits (short labels, a single choice). Behaviour and stored values
are unchanged. Each panel's existing e2e is updated only for the locator change
(`getByRole("combobox")` and option clicks instead of `selectOption`).

## 6. Failure behaviour

- **Unknown stored values:** a stored value that is not in a control's options is
  shown as a selected extra option, never silently replaced. Saving without
  touching the control keeps it. This applies to old dashboards, hand-edited
  layouts and removed rules.
- **Data that fails to load:** if options that depend on data (rule sets, rules)
  fail, the control shows the stored value with "(could not load)" and stays
  usable.

## 7. Testing

- **Unit (vitest):**
  - `Select` keyboard, search, groups, aria and the unknown-value case;
  - `Segmented` and `Switch` keyboard and aria;
  - the filter catalogue: round-trip `query` ↔ chips, with unknown params kept;
  - first-free-spot placement;
  - the guard that no native select or unstyled checkbox, radio or number input
    is left.
- **Demo e2e:**
  - every widget editor with the new controls, including the Graph count rows
    (add, remove, colour dot) and List filters (add, remove, changing the list
    drops unsupported filters);
  - the panel header name;
  - a pencil, not a funnel;
  - new-widget placement;
  - existing e2e updated for the new locators;
  - axe with no violations, light and dark.
- **Live e2e:** the existing suite, updated for the locators.
- **Visual check:** light and dark, at 1440 and 390 px. This covers each editor,
  an open `Select` with groups and search, and the Add widget list with the new
  icons.

## 8. Out of scope

- **New filters:** the editor offers only what the list views already support.
- **Dashboard sharing and permissions:** unchanged.
- **The Pages size problem:** a separate decision before the release.
