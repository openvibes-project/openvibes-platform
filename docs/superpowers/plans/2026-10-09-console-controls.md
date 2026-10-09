# Console controls — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** No browser-drawn control anywhere in the console, and widget editors that show names and words instead of ids and query syntax.

**Architecture:**
- Three shared controls in `src/ui/`: `Select` (generalised from `Picker`, with groups and search), `Segmented` (a button row) and `Switch`.
- CSS classes for the checkboxes and number inputs that remain.
- One filter catalogue per list (`src/views/filters.ts`), used by both the list views and the List editor.
- The editors, tiles and the 18 other native selects are moved onto these.
- A guard test keeps native controls from coming back.

**Tech Stack:** React 18 + TypeScript (Vite), vitest, Playwright (demo and live e2e), plain CSS with the tokens in `src/styles/tokens.css`.

**Spec:** `docs/superpowers/specs/2026-10-09-console-controls-design.md` (approved; the mockups are referenced at the top).

All paths below are relative to `crates/openvibes-console/web/` unless they start with `docs/`.

## Global Constraints

- **Native controls:** no `<select>` element anywhere in `src/**/*.tsx` at the end. Every `<input type="checkbox">` carries `className` containing `checkbox`. Every `<input type="number">` carries `className` containing `input`, and the CSS hides the spinners. No `type="radio"`.
- **Colours:** only tokens from `src/styles/tokens.css` (light, dark, and `:root[data-theme]` variants). No hex values in components.
- **Stored values:** stored configs and API payloads keep their current shapes. List keeps `view` and `query`, Trend keeps `finding` as `set/rule`, and numbers stay numbers.
- **Unknown values:** a stored value that is not in a control's options is shown as a selected extra option and kept on save (spec §6).
- **Wording:** user-visible text uses "compliance findings", never a bare "findings". Labels are short and plain.
- **Phone:** everything works at 390 px wide, with no horizontal page scroll.
- **Tests:**
  - `npm run lint`, `npm run typecheck` and vitest stay green.
  - The demo e2e runs in Chromium and Firefox; the live e2e runs via `scripts/test-console-e2e.sh`.
  - axe reports no violations in light and dark.
- **Commits:** end with `Co-Authored-By: Claude <noreply@anthropic.com>`. No push.

## Review Focus

1. **Keyboard-only use of `Select` inside the inspector:** opening, searching, picking and Esc must return focus to the button. A popup must never be clipped by the inspector's scroll box at 390 px. Tested in Task 1.
2. **A dashboard saved before this change:** List `query=bad=1&severity=critical`, Number `trend: 14`, attention `limit: 12`. It shows the odd values as selected extras and saves them back unchanged unless edited. Tested in Task 4.
3. **Changing the List editor's list from Compliance findings to Hosts:** drops `severity` (Hosts has no severity filter) and keeps unknown chips. Tested in Task 3/4.
4. **Two `Select`s open on one panel:** opening one closes the other. Outside click and Tab close it. Tested in Task 1.
5. **Case and alarm panels** (moved in Task 6): a triage action through the new `Select` still sends the same API body as before. Tested by the existing e2e with updated locators plus one body assertion in Task 6.

---

### Task 1: `Select`, the console dropdown

**Files:**
- Create: `src/ui/Select.tsx`, `src/ui/select.test.tsx`
- Modify: `src/ui/Picker.tsx` (becomes `export const Picker = Select`-style wrapper or is deleted with its one caller moved), `src/panels/FindingPanel.tsx` (Picker caller), `src/styles/components.css` (`.picker*` → `.sel*` rules: popup, group heading, option, active, selected tick, search)

**Interfaces:**
- Produces:
  ```ts
  export type SelectOption = { value: string; label: string; disabled?: boolean };
  export type SelectGroup = { group: string; options: SelectOption[] };
  export function Select(props: {
    label: string;                 // accessible name (and visible label is the caller's `field`)
    value: string;
    onChange: (value: string) => void;
    options: SelectOption[] | SelectGroup[];
    placeholder?: string;
    unknownLabel?: (value: string) => string; // default: (v) => v — shown as a selected extra option when value ∉ options
    small?: boolean;               // the existing `.select--small` size
    disabled?: boolean;
  }): JSX.Element;
  ```
- **Search:** appears when there are more than 8 enabled options in total.

- [ ] **Step 1: Write the failing tests** in `src/ui/select.test.tsx` (vitest + @testing-library/react, as other `*.test.tsx` in the repo; if none use RTL, render with `react-dom/client` into a jsdom container and dispatch events — follow `src/ui/table.test.ts` conventions for setup):
  1. Closed button shows the selected label; `role="combobox"`, `aria-expanded="false"`.
  2. Click opens a `listbox`; groups render as `role="group"` with `aria-label` = group name; headings are not options.
  3. ArrowDown/ArrowUp skip headings and disabled options; Enter picks and closes; `onChange` called once with the value.
  4. Escape closes and focus returns to the button; Tab closes.
  5. With 9+ options a search box appears and filters across groups, hiding empty groups; "No match" when nothing matches; with ≤ 8 no search box.
  6. Typing a letter on the closed, focused button opens it with the search pre-filled.
  7. `value` not in options → the button shows `unknownLabel(value)` and the list contains it as a selected option at the top; picking it calls nothing.
  8. Opening a second `Select` closes the first (document-level single-open: a module-level "close current" callback).
- [ ] **Step 2:** `npx vitest run src/ui/select.test.tsx` → FAIL.
- [ ] **Step 3: Implement** `Select` by generalising `Picker`:
  - Keep its keyboard handling, `scrollIntoView` and outside-pointer close.
  - Add groups, conditional search, unknown value, `small` and `disabled`.
  - Place the popup by measuring with `getBoundingClientRect` on open. It opens downwards unless the space below is under 220 px and there is more space above. Use `position: fixed` with the button's left and width, clamped to the viewport, so the inspector's `overflow` cannot clip it. Recompute on scroll and resize, or close on scroll as `AddToCase` does (`src/panels/AddToCase.tsx` closes on outside scroll).
  - CSS:
    - Closed button: reuse `.select`, plus `.sel__button` for a flex row with the chevron icon `chevronDown`.
    - Popup: `.sel__popup` (surface, `--line-strong`, radius 8 px, shadow `0 8px 24px rgb(0 0 0 / .45)`).
    - Group heading: `.sel__group` (10.5 px, `letter-spacing: .06em`, `--text-3`, weight 600).
    - Option: `.sel__option`; active uses `--accent-soft`; `[aria-selected=true]` uses weight 600 and an accent `check` icon.
- [ ] **Step 4:** Move `FindingPanel`'s `Picker` to `Select`, and delete `Picker.tsx` along with the `.picker*` CSS. Run the existing FindingPanel e2e locally (`npx playwright test e2e/demo -g "finding"` with the demo config) → PASS.
- [ ] **Step 5:** Run `npx vitest run`, `npm run lint` and `npm run typecheck` → PASS.
- [ ] **Step 6: Commit:** "Console: Select, the console's own dropdown (groups, search, keyboard)".

### Task 2: `Segmented`, `Switch`, checkbox and number styles

**Files:**
- Create: `src/ui/Segmented.tsx`, `src/ui/Switch.tsx`, `src/ui/controls.test.tsx`
- Modify: `src/styles/components.css`

**Interfaces:**
- Produces:
  ```ts
  export function Segmented<T extends string | number>(props: { label: string; value: T; onChange: (v: T) => void; options: { value: T; label: string }[]; unknownLabel?: (v: T) => string }): JSX.Element;
  export function Switch(props: { label: string; checked: boolean; onChange: (checked: boolean) => void; disabled?: boolean }): JSX.Element;
  ```
- **CSS classes:**
  - `.seg` and `.seg__opt` (and `[aria-checked=true]`);
  - `.switch`, `.switch__track` and `.switch__knob` (track 30 × 17, on = `--accent`, knob dark `--accent-text`);
  - `.checkbox` (`appearance: none`, 16 px, radius 4 px, border `--line-strong`; checked = `--accent` fill with a dark tick drawn by a CSS mask or `::after` border; focus ring as `.input:focus`);
  - `input.input[type=number]` hides the spinners (`-moz-appearance: textfield`; `::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0 }`).

- [ ] **Step 1: Write the failing tests** in `src/ui/controls.test.tsx`:
  - **Segmented:**
    - it is a `radiogroup` whose options are `radio`s with the right `aria-checked`;
    - clicking calls `onChange`;
    - ArrowRight and ArrowLeft move the selection and wrap;
    - a value not in the options renders as an extra checked option with `unknownLabel` (default `String(v)`).
  - **Switch:** it is a `switch` with `aria-checked`; clicking the row or pressing Space toggles it; when disabled, nothing happens.
- [ ] **Step 2:** `npx vitest run src/ui/controls.test.tsx` → FAIL.
- [ ] **Step 3:** Implement the two components and the CSS. At 390 px the segment labels stay on one line (`white-space: nowrap`); options share the width (`flex: 1`).
- [ ] **Step 4:** `npx vitest run`, lint, typecheck → PASS.
- [ ] **Step 5: Commit:** "Console: button row, switch, styled checkbox and number inputs".

### Task 3: One filter catalogue per list

**Files:**
- Create: `src/views/filters.ts`, `src/views/filters.test.ts`
- Modify: `src/views/Findings.tsx`, `src/views/Vulnerabilities.tsx`, `src/views/Agents.tsx`, `src/views/Admin.tsx` (audit chips at ~211-212)

**Interfaces:**
- Produces:
  ```ts
  export type FilterDef =
    | { param: string; label: string; kind: "flag"; value: string }                       // e.g. exploited=true → "Known exploited"
    | { param: string; label: string; kind: "choice"; values: { value: string; label: string }[] }; // e.g. severity
  export const LIST_FILTERS: Record<ListView, FilterDef[]>;
  export const LIST_LABELS: Record<ListView, string>; // "Compliance findings", "Vulnerabilities", "Hosts", "Audit log"
  export type Chip = { param: string; value: string; label: string; known: boolean };
  export function chipsOf(view: ListView, query: string): Chip[];      // unknown params → known:false, label `${param}=${value}`
  export function queryOf(chips: Chip[]): string;                       // stable order: catalogue order, then unknowns
  export function dropUnsupported(view: ListView, query: string): string; // keeps unknown params, drops known params the view lacks
  ```
- **Catalogue contents,** taken from today's inline chip arrays; values must match exactly:
  - `/compliance`: `state` flag `all` "Include resolved"; `severity` choice critical, high, medium, low (labels capitalised). The rule-set chips (`set`) are computed at runtime from data and are NOT in the catalogue, so the editor does not offer them; a stored `set=` shows as an unknown chip.
  - `/vulnerabilities`: flags `exploited=true` "Known exploited", `reboot=true` "Reboot needed", `nofix=true` "No fix yet" and `lowconf=true` "Lower confidence"; `severity` choice critical, important, moderate, low.
  - `/agents`: `status` choice active "Online", stale "Stale", imported "Imported", revoked "Revoked".
  - `/audit`: `result` flag `failure` "Failures"; `range` choice 1 "Last day", 7 "Last 7 days", 365 "Last 365 days".
- **Runtime counts:** the views keep them by mapping catalogue entries to their existing chip objects (`{ label, param, value, count }`).

- [ ] **Step 1: Write the failing tests** in `src/views/filters.test.ts`:
  - `chipsOf("/vulnerabilities", "severity=critical&exploited=true&bad=1")` returns the labels "Severity: Critical", "Known exploited" and "bad=1" (known false);
  - `queryOf(chipsOf(v, q))` round-trips to the stable order;
  - `dropUnsupported("/agents", "severity=critical&bad=1&status=stale")` returns `"status=stale&bad=1"`;
  - every catalogue value appears in the corresponding view's rendered chips. This is a source-level check: import the catalogue in the view and assert in the test that each view module uses `LIST_FILTERS[...]`. A grep in the test is acceptable, as `catalogue.test.ts` does for metrics.rs.
- [ ] **Step 2:** `npx vitest run src/views/filters.test.ts` → FAIL.
- [ ] **Step 3:** Implement `filters.ts`, then switch the four views to build their chip bars from `LIST_FILTERS`. Labels and order stay exactly as today, and runtime extras (rule sets, counts) are appended as now.
- [ ] **Step 4:** Run vitest and the demo e2e specs for these views (`npx playwright test -c playwright.demo.config.ts e2e/demo/{findings,vulnerabilities,agents,admin}*`, using the real file names in `e2e/demo/`) → PASS, with no visible change.
- [ ] **Step 5: Commit:** "Console: one filter catalogue per list".

### Task 4: Widget editors

**Files:**
- Modify: `src/dashboards/tiles2.tsx` (all `*Settings`), `src/app/registry.tsx:102` (widget panel title), `src/styles/panels.css` (editor rows), `src/dashboards/metrics.ts` (a `METRIC_GROUPS` export if no grouping exists)
- Test: `src/dashboards/settings.test.tsx` (new), `e2e/demo/dashboards.spec.ts`, `e2e/demo/charts.spec.ts`

**Interfaces:**
- Consumes: `Select`, `SelectGroup` (Task 1); `Segmented`, `Switch` (Task 2); `LIST_FILTERS`, `LIST_LABELS`, `chipsOf`, `queryOf` and `dropUnsupported` (Task 3); `graphLabel`, `graphMetrics` and `METRICS` (`src/dashboards/metrics.ts`); `WIDGETS` (`src/dashboards/widgets.tsx`).
- Produces:
  ```ts
  export const METRIC_GROUPS: SelectGroup[]; // All kinds, Alarms, Vulnerabilities, Compliance, Hosts — built from METRICS by id prefix (all.*, alarms.*, vulns.*, compliance.*, hosts.*) with graphLabel for labels
  ```
- **Widget panel title** (`registry.tsx`): `title: (id) => \`Edit widget · ${WIDGETS[id.replace(/-\d+$/, "") as WidgetType]?.label ?? "Widget"}\`` and `icon: "pencil"`. The pencil icon is added in Task 5, so until then use `"filter"` here and switch it in Task 5. `top-hosts-1` maps to `top-hosts`.

- [ ] **Step 1: Write the failing unit tests** in `settings.test.tsx`, rendering each Settings component with a widget and an `onChange` spy:
  - **Graph:**
    - three counts render three rows, each with a colour dot (`--series-1..3`), a combobox and a "Remove count N" button;
    - "＋ Add a count" is hidden at 4;
    - an already-used count is disabled in the other rows.
  - **Graph Period and Line:** both are radiogroups.
  - **Number Trend:** a radiogroup (Off, 7 d, 30 d, 90 d). A stored `trend: 14` shows "14 d" as an extra checked option, and saving without a change keeps 14 (Review Focus 2).
  - **Attention:** one `switch` per kind. Show at most is a radiogroup 5, 8, 10, 15, and a stored 12 shows as an extra.
  - **List:**
    - the list combobox shows "Compliance findings";
    - stored `query "severity=critical&bad=1"` gives the chips "Severity: Critical" and "bad=1", each with a remove button;
    - "＋ Add filter" opens a menu of the catalogue entries not yet used; picking a choice filter then asks for its value;
    - switching the list to Hosts calls `onChange` with the query passed through `dropUnsupported` (Review Focus 3).
  - **Trend rule:** a searchable combobox. A stored `finding` that is not among the loaded rules shows "<set/rule> (not found)".
  - **Top hosts:** Count is a radiogroup (All kinds, Vulnerabilities only); Hosts is a radiogroup 3, 6, 10.
  - **Breakdown:** a radiogroup with Alarms, Vulnerabilities, Compliance and Hosts.
- [ ] **Step 2:** `npx vitest run src/dashboards/settings.test.tsx` → FAIL.
- [ ] **Step 3: Implement.**
  - **Trend rules:** load them with the existing compliance list fetch used by the Findings view (the summary of finding groups gives `rule_set`, `rule_id` and a title), as `{ group: rule_set, options: [{ value: "set/rule", label: title }] }`.
  - **Load errors:** on a load error the stored value shows with "(could not load)".
  - **Layout:**
    - `.editor-count` row: grid `10px 1fr 32px`, gap 6 px;
    - the ✕ is an `icon-button` with the `close` icon;
    - `.link-add` is an accent text button with the `plus` icon.
  - **Remove widget:** keep it as the existing danger button.
- [ ] **Step 4: Update the e2e:**
  - In `charts.spec.ts`, use comboboxes and options instead of `selectOption`, "＋ Add a count", and "Remove count N".
  - In `dashboards.spec.ts`, add the panel header "Edit widget · Graph" (not `graph-1`).
  - Add one new demo test that seeds a dashboard with odd stored values. Use the editor JSON route the demo exposes, or local storage as other dashboard e2e tests do. Check that saving without edits keeps them, by reading the saved layout from the demo store.
  - Run the full demo e2e (`npm run test:e2e:demo`) → PASS.
- [ ] **Step 5:** Run vitest, lint and typecheck → PASS.
- [ ] **Step 6: Commit:** "Dashboards: editors use the console controls; List filters as chips; Trend picks a rule; header names the widget".

### Task 5: Tiles and page

**Files:**
- Modify: `src/ui/Icon.tsx` (add icons), `src/dashboards/Grid.tsx:89`, `src/dashboards/DashboardsView.tsx:159,170`, `src/app/registry.tsx` (widget icon), `src/dashboards/widgets.tsx:22-29` (icons), `src/dashboards/layout.ts:110-116` (`addWidget`), `src/views/rows.ts:126` (List tile severity badge)
- Test: `src/dashboards/grid.test.ts`, `src/views/rows.test.ts`, `e2e/demo/dashboards.spec.ts`

**Interfaces:**
- **New icons** in `paths`, drawn in Lucide style on the 24 px grid. Use Lucide's MIT shapes, as the file header already credits:
  - `pencil`: Lucide "pencil";
  - `hash`: Lucide "hash", for Number;
  - `chartBar`: Lucide "bar-chart-3", for Trend;
  - `chartLine`: Lucide "line-chart", for Graph;
  - `list`: Lucide "list", for List;
  - `barStacked`: Lucide "align-left", for Breakdown;
  - `note`: Lucide "sticky-note", for Note.
  - Needs attention keeps `alert` and Most exposed hosts keeps `agents`.
- **Placement:** `addWidget` places the widget at the first free spot, scanning `y` from 0 and `x` from 0 to `COLUMNS - w`, where a `w × h` rectangle overlaps no widget. If nothing fits above the bottom, it goes at the bottom, as today. The `y` cap at 199 stays.

- [ ] **Step 1: Write the failing tests:**
  - `grid.test.ts`: adding a 3 × 4 widget to a layout that has one 3 × 4 widget at (0, 0) places it at (3, 0). A 12-wide widget goes below. The existing "adds at the bottom with a unique id" test changes to "adds at the first free spot with a unique id".
  - `rows.test.ts`: the List row badge for `severity: "critical"` has the label "Critical".
- [ ] **Step 2:** Run them → FAIL.
- [ ] **Step 3: Implement.**
  - Icons: replace the `filter` icon with `pencil` on the tile settings button, the page Edit button, the Rename menu item and the widget panel icon.
  - Set each widget type's icon in `widgets.tsx`.
  - Change the placement code in `addWidget`.
  - Capitalise the List row badge label: the first letter upper-cased, the tone unchanged. Use the same helper as `SeverityBadge` if there is one; otherwise add `capitalise` in `src/ui/format.ts`.
- [ ] **Step 4: e2e** (`dashboards.spec.ts`):
  - The Edit button contains the pencil, not the funnel: `[data-icon=pencil]` if `Icon` renders `data-icon`; otherwise add `data-icon={name}` to `Icon`.
  - Adding two Number widgets puts them side by side (same `y`).
  - Run the full demo e2e → PASS.
- [ ] **Step 5: Commit:** "Dashboards: pencil for edit, one icon per widget, new widgets fill the first free spot".

### Task 6: The rest of the console

**Files:**
- Modify (native selects, 18):
  - `src/panels/AdminPanels.tsx:64,96,304`
  - `src/panels/AlarmPanel.tsx:104,111`
  - `src/panels/SiteRulePanel.tsx:70,159`
  - `src/panels/CasePanel.tsx:53,86,161,201,251,329`
  - `src/panels/OpsPanels.tsx:140,272,273`
  - `src/views/Alarms.tsx:85`
  - `src/panels/FindingPanel.tsx:164`
- Modify (checkboxes):
  - `src/panels/AgentPanel.tsx:39`
  - `src/panels/HostExport.tsx:107`
  - `src/panels/FindingPanel.tsx:186,194`
  - `src/ui/DataTable.tsx:91,117`
- Modify (number inputs; keep them as styled inputs, since their ranges are too wide for a button row):
  - `src/panels/AdminPanels.tsx:194`
  - `src/panels/OpsPanels.tsx:139`
  - `src/panels/SiteRulePanel.tsx:160`
- Create: `src/ui/no-native-controls.test.ts`
- Test: the e2e specs for these panels in `e2e/demo/` and `e2e/live/`

**Interfaces:** consumes `Select`, `Segmented` and the `.checkbox` class.

**Rule per select:** choices with 2–4 short options, one value, and no data dependency become `Segmented`. Everything else becomes `Select`. Keep `small` where the select had `select--small` (the Alarms table quiet menu and the Case item outcome).

- [ ] **Step 1: Write the guard test** `src/ui/no-native-controls.test.ts`:
  - read every `src/**/*.tsx` with `fs`;
  - fail on `/<select[\s>]/`;
  - fail on `type="checkbox"` without `checkbox` in the same element's `className`;
  - fail on `type="radio"`;
  - fail on `type="number"` without `input` in the same element's `className`.
  - The match is per opening tag; a simple regex over `<input[^>]*>` is enough.
  - It lists file:line for each violation.
  - Run it → FAIL, listing the 18 selects and the unstyled checkboxes.
- [ ] **Step 2:** Move each select per the rule. Labels stay the same, `onChange` receives the same value, and disabled states are kept. Add `className="checkbox"` to the checkboxes.
- [ ] **Step 3:** Update the e2e locators: `selectOption` becomes `getByRole("combobox", { name })`, then a click on `getByRole("option", { name })`, or `getByRole("radio", { name })` for button rows. Add one assertion to the case-triage e2e that the request body sent after picking an outcome equals the previous shape (Review Focus 5), using `page.waitForRequest`.
- [ ] **Step 4:** Run vitest (the guard now passes), lint, typecheck, the full demo e2e, and the live e2e (`eval "$(scripts/test-db.sh)"; bash scripts/test-console-e2e.sh` from the worktree root; WebKit "missing dependencies" is acceptable) → PASS.
- [ ] **Step 5: Commit:** "Console: no native selects, checkboxes or spinners left (guarded by a test)".

### Task 7: Docs, visual check, gate

**Files:**
- Modify: `docs/components/console-web.md` (controls section: Select, Segmented, Switch, the guard; the filter catalogue; the editors), `docs/components/console-dashboards.md` (editor behaviour, placement, unknown values)

- [ ] **Step 1: Docs,** written from the code as it now is.
- [ ] **Step 2: Visual check.** Use a scripted Playwright run against the demo build, writing screenshots to the scratchpad (not committed). Cover light and dark, at 1440 and 390 px:
  - each widget editor;
  - an open `Select` with groups and search;
  - the Add widget list;
  - a dashboard with new widgets placed;
  - the case panel and the alarm panel with the new controls.

  Compare against the mockups. Report differences, and fix them if they are clear.
- [ ] **Step 3: Gate** (`testing.md` §2), run in the background and waited on properly, capturing every `test result` line.
- [ ] **Step 4: Commit the docs:** "Docs: console controls".
