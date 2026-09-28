# Console Dashboards, part 3b of 3: Editor and Dashboard View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Dashboards become the console's home. The built-in Overview
turns into a dashboard, and users can switch, create, duplicate, edit
(drag, resize, keyboard), save with conflict handling, share with a role,
and set a home.

**Architecture:**
- An editor store (`dashboards/editor.ts`) holds the draft. The grid,
  the gallery panel and the settings panel all read and change it.
- `DashboardsView` owns the route `/` (home) and `/dashboards/{id}`.
- Widget settings open in the inspector, like every other detail.

**Tech Stack:** React 19, TypeScript, Vitest, Playwright with axe.

**Spec:** `docs/superpowers/specs/2026-09-28-console-dashboards-design.md`
(§2, §3). It depends on parts 1, 2 and 3a.

## Global Constraints

- **Routes:**
  - `/` shows the home dashboard (`GET /api/v1/me/home`, where `null` is
    the built-in);
  - `/dashboards/overview` is the built-in;
  - `/dashboards/{id}` is a stored dashboard.
- **Rail:** "Dashboards" replaces "Overview", shortcut `g d`. Every
  signed-in user may open it.
- **The built-in Overview:**
  - read-only;
  - its header keeps the greeting, "Good …, {first name}", as the `h1`;
  - "Duplicate to edit" creates "Copy of Overview".
- **Shared dashboards (`mine: false`):** read-only, with "Duplicate to
  edit".
- **Saving:**
  - `PUT` with `If-Match: "<version>"`;
  - 412 shows "Someone saved this dashboard since you opened it" and
    offers "Reload theirs" or "Save as a copy";
  - edits are kept until the user chooses.
- **Editing:**
  - edit mode only; view mode never moves tiles;
  - tiles move by dragging the header and resize by dragging the corner;
  - with a tile focused: arrows move, Shift+arrows resize, Delete
    removes, Enter opens its settings;
  - editing is hidden below 720 px, where tiles stack.
- A tile that throws renders "This tile failed to show", and the others
  keep working.
- **Share menu:** only for the owner, and only with global
  `dashboards.share`. The roles offered are `viewer`, `analyst`,
  `operator`, `admin`, or "Not shared".
- **Gate:**
  - `npx vitest run --config vite.v2.config.ts`;
  - `npx eslint . --max-warnings 0`;
  - `npx tsc --noEmit`;
  - `npx playwright test --config playwright.v2.config.ts`, in both
    browsers, with axe in both themes on the view and in edit mode;
  - `bash scripts/build-console.sh`.
- **Commits** end with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Navigating away with unsaved edits** (the rail, the palette or the
   Back button) must not silently throw them away. The view asks with
   `window.confirm` when the editor is dirty. Tested in Task 4
   (`asks before leaving unsaved edits`).
2. **A home dashboard that was deleted, or unshared from you,** falls
   back to the built-in without an error. The server already returns
   `null`; `/` then renders the built-in. Tested in Task 4
   (`home falls back to the built-in`).
3. **A tile component that throws** must not blank the dashboard. There
   is an error boundary per tile. Tested in Task 2 (`one broken tile
   leaves the rest`).
4. **Editing the built-in by URL tricks** (`/dashboards/overview` in
   edit mode) is impossible: the editor refuses to begin on built-in or
   shared dashboards. Tested in Task 1 (`refuses to edit what you do not
   own`).
5. **A save that returns 422** (for example, the server's layout rules
   are stricter than an old UI's) shows the field problems and keeps the
   draft. Tested in Task 1 (`shows server problems and keeps the draft`).

---

### Task 1: Built-in layout, dashboard types and the editor store

**Files:**
- Create: `crates/openvibes-console/web/v2/src/dashboards/builtin.ts`
- Create: `crates/openvibes-console/web/v2/src/dashboards/editor.ts`
- Modify: `crates/openvibes-console/web/v2/src/dashboards/widgets.tsx` (`widgetTitle` uses the metric label for `number`)
- Test: `crates/openvibes-console/web/v2/src/dashboards/editor.test.ts`

**Interfaces:**
- Consumes:
  - `Layout`, `validateLayout`, `validateName`, `addWidget`, `moveWidget`, `resizeWidget`, `removeWidget` (`layout.ts`);
  - `widgetDefs` (3a);
  - `request`, `invalidate`, `ApiError` (`api/client.ts`);
  - `Dashboard` (`api/types.ts`, part 2).
- Produces:
  - `builtin.ts`: `export const BUILTIN_ID = "overview"; export const BUILTIN_NAME = "Overview"; export const BUILTIN_LAYOUT: Layout`
  - `editor.ts`:
    - `export type EditorState = { dashboard: Dashboard | null; name: string; draft: Layout | null; dirty: boolean; saving: boolean; conflict: boolean; problems: FieldProblem[]; selected: string | null }`
    - `export const editor = { begin(d: Dashboard): boolean; cancel(): void; rename(name: string): void; change(layout: Layout): void; add(type: WidgetType): string; configure(id: string, config: Widget["config"]): void; remove(id: string): void; select(id: string | null): void; save(): Promise<Dashboard | undefined>; saveAsCopy(): Promise<Dashboard | undefined>; reloadTheirs(): Promise<void> }`
    - `export function useEditor(): EditorState`

- [ ] **Step 1: Write the failing tests**

```ts
import { beforeEach, describe, expect, it } from "vitest";

import { configureDemo, request } from "../api/client";
import type { Dashboard } from "../api/types";
import { BUILTIN_LAYOUT } from "./builtin";
import { editor, editorState } from "./editor";
import { validateLayout } from "./layout";

const layout = { schema: 1 as const, widgets: [{ id: "w1", type: "number" as const, x: 0, y: 0, w: 3, h: 2, config: { metric: "agents.active" } }] };

describe("editor", () => {
  beforeEach(() => { configureDemo("admin"); editor.cancel(); });

  it("the built-in Overview is a valid layout", () => {
    expect(validateLayout(BUILTIN_LAYOUT)).toEqual([]);
  });

  it("refuses to edit what you do not own", async () => {
    configureDemo("analyst");
    const items = (await request<{ items: Dashboard[] }>("GET", "/api/v1/dashboards")).items;
    const shared = items.find((d) => !d.mine);
    expect(shared).toBeDefined();
    expect(editor.begin(shared as Dashboard)).toBe(false);
    expect(editorState().draft).toBeNull();
  });

  it("adds, configures and saves with the version", async () => {
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Mine", layout });
    expect(editor.begin(created)).toBe(true);
    const id = editor.add("note");
    editor.configure(id, { text: ["hello"] });
    const saved = await editor.save();
    expect(saved?.version).toBe(2);
    expect(saved?.layout.widgets).toHaveLength(2);
    expect(editorState().dirty).toBe(false);
  });

  it("flags a conflict on 412 and keeps the draft, then saves a copy", async () => {
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Shared tab", layout });
    editor.begin(created);
    editor.rename("From tab one");
    await request("PUT", `/api/v1/dashboards/${created.dashboard_id}`, { name: "From tab two", layout }, { "if-match": '"1"' });
    expect(await editor.save()).toBeUndefined();
    expect(editorState()).toMatchObject({ conflict: true, name: "From tab one", dirty: true });
    const copy = await editor.saveAsCopy();
    expect(copy).toMatchObject({ name: "From tab one", mine: true, version: 1 });
  });

  it("shows server problems and keeps the draft", async () => {
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Valid", layout });
    editor.begin(created);
    editor.rename("   ");
    expect(await editor.save()).toBeUndefined();
    expect(editorState().problems.map((p) => p.field)).toEqual(["name"]);
    expect(editorState().draft).not.toBeNull();
  });
});
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `npx vitest run --config vite.v2.config.ts src/dashboards/editor`
Expected: FAIL, "Cannot find module './editor'".

- [ ] **Step 3: Implement**

`builtin.ts`:

```ts
// The built-in Overview: not stored, not editable, updated with releases.
// "Duplicate to edit" makes a stored copy of this layout.
import type { Layout } from "./layout";

export const BUILTIN_ID = "overview";
export const BUILTIN_NAME = "Overview";
export const BUILTIN_LAYOUT: Layout = {
  schema: 1,
  widgets: [
    { id: "online", type: "number", x: 0, y: 0, w: 2, h: 2, config: { metric: "agents.active" } },
    { id: "stale", type: "number", x: 2, y: 0, w: 2, h: 2, config: { metric: "agents.stale" } },
    { id: "critical", type: "number", x: 4, y: 0, w: 2, h: 2, config: { metric: "findings.open.critical" } },
    { id: "high", type: "number", x: 6, y: 0, w: 2, h: 2, config: { metric: "findings.open.high" } },
    { id: "exploited", type: "number", x: 8, y: 0, w: 2, h: 2, config: { metric: "vulns.exploited" } },
    { id: "reboot", type: "number", x: 10, y: 0, w: 2, h: 2, config: { metric: "vulns.reboot_hosts" } },
    { id: "attention", type: "attention", x: 0, y: 2, w: 7, h: 9, config: { include: ["exploited", "findings", "stale"], limit: 14 } },
    { id: "findings", type: "breakdown", x: 7, y: 2, w: 5, h: 3, config: { source: "findings" } },
    { id: "hosts", type: "top-hosts", x: 7, y: 5, w: 5, h: 6, config: { limit: 6 } },
  ],
};
```

`editor.ts`:

```ts
// The dashboard being edited: one draft at a time, shared by the grid, the
// widget gallery and the settings panels. Only the owner may edit; saves
// carry the version so a second tab cannot overwrite silently.
import { useSyncExternalStore } from "react";

import { ApiError, invalidate, request } from "../api/client";
import type { Dashboard } from "../api/types";
import { type FieldProblem, type Layout, type Widget, type WidgetType, addWidget, removeWidget, validateLayout, validateName } from "./layout";
import { widgetDefs } from "./widgets";

export type EditorState = {
  dashboard: Dashboard | null; name: string; draft: Layout | null; dirty: boolean;
  saving: boolean; conflict: boolean; problems: FieldProblem[]; selected: string | null;
};

const empty: EditorState = { dashboard: null, name: "", draft: null, dirty: false, saving: false, conflict: false, problems: [], selected: null };
let state = empty;
const listeners = new Set<() => void>();
const set = (next: Partial<EditorState>) => { state = { ...state, ...next }; for (const listener of listeners) listener(); };
export const editorState = () => state;

function problemsOf(error: unknown): FieldProblem[] {
  const details = (error as { fieldErrors?: FieldProblem[] }).fieldErrors;
  return details ?? [{ field: "dashboard", code: "save_failed", message: error instanceof Error ? error.message : "Save failed" }];
}

export const editor = {
  begin(dashboard: Dashboard): boolean {
    if (!dashboard.mine) return false;
    set({ ...empty, dashboard, name: dashboard.name, draft: dashboard.layout as Layout });
    return true;
  },
  cancel() { set(empty); },
  rename(name: string) { set({ name, dirty: true }); },
  change(layout: Layout) { set({ draft: layout, dirty: true }); },
  add(type: WidgetType): string {
    const def = widgetDefs[type];
    const { layout, id } = addWidget(state.draft ?? { schema: 1, widgets: [] }, type, def.size, def.defaults);
    set({ draft: layout, dirty: true, selected: id });
    return id;
  },
  configure(id: string, config: Widget["config"]) {
    if (!state.draft) return;
    set({ draft: { ...state.draft, widgets: state.draft.widgets.map((w) => (w.id === id ? { ...w, config } : w)) }, dirty: true });
  },
  remove(id: string) {
    if (!state.draft) return;
    set({ draft: removeWidget(state.draft, id), dirty: true, selected: state.selected === id ? null : state.selected });
  },
  select(id: string | null) { set({ selected: id }); },
  async save(): Promise<Dashboard | undefined> {
    const { dashboard, draft } = state;
    if (!dashboard || !draft) return undefined;
    const name = validateName(state.name);
    const problems = [...(typeof name === "string" ? [] : [name]), ...validateLayout(draft)];
    if (problems.length) { set({ problems }); return undefined; }
    set({ saving: true, problems: [] });
    try {
      const saved = await request<Dashboard>("PUT", `/api/v1/dashboards/${dashboard.dashboard_id}`, { name, layout: draft }, { "if-match": `"${dashboard.version}"` });
      invalidate("/api/v1/dashboards");
      set({ ...empty });
      return saved;
    } catch (error) {
      if (error instanceof ApiError && error.status === 412) set({ saving: false, conflict: true });
      else set({ saving: false, problems: problemsOf(error) });
      return undefined;
    }
  },
  async saveAsCopy(): Promise<Dashboard | undefined> {
    if (!state.draft) return undefined;
    set({ saving: true });
    try {
      const copy = await request<Dashboard>("POST", "/api/v1/dashboards", { name: state.name.trim() || "Untitled dashboard", layout: state.draft });
      invalidate("/api/v1/dashboards");
      set({ ...empty });
      return copy;
    } catch (error) {
      set({ saving: false, problems: problemsOf(error) });
      return undefined;
    }
  },
  async reloadTheirs() {
    if (!state.dashboard) return;
    invalidate(`/api/v1/dashboards/${state.dashboard.dashboard_id}`);
    const fresh = await request<Dashboard>("GET", `/api/v1/dashboards/${state.dashboard.dashboard_id}`);
    editor.begin(fresh);
  },
};

export function useEditor(): EditorState {
  return useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, () => state);
}
```

`ApiError` does not carry `field_errors` yet. Extend it in
`api/client.ts`: add a constructor parameter
`readonly fieldErrors?: { field: string; code: string; message: string }[]`,
and pass `details.field_errors` when building it in `request`. The
existing calls still compile because the parameter is optional. In
`editor.ts`, `problemsOf` then reads `error.fieldErrors` when `error
instanceof ApiError`.

In `widgets.tsx`, change `widgetTitle`:

```ts
export function widgetTitle(widget: Widget): string {
  const custom = widget.config.title;
  if (typeof custom === "string" && custom.trim()) return custom.trim();
  if (widget.type === "number") return METRICS[str(widget.config, "metric", "agents.active", METRIC_KEYS)].label;
  return widgetDefs[widget.type].label;
}
```

(import `METRICS`, `METRIC_KEYS` from `./tiles` and `str` from `./config`).

- [ ] **Step 4: Run the tests and watch them pass**

Run: `npx vitest run --config vite.v2.config.ts src/dashboards`
Expected: all pass, 5 of them new.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-console/web/v2/src
git commit -m "Console v2: built-in Overview layout and the dashboard editor store

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: The grid component

**Files:**
- Create: `crates/openvibes-console/web/v2/src/dashboards/Grid.tsx`
- Modify: `crates/openvibes-console/web/v2/src/styles/panels.css` (grid and tile styles)

**Interfaces:**
- Consumes: `Layout`, `COLUMNS`, `ROW_HEIGHT`, `moveWidget`, `resizeWidget`, `readingOrder` (3a); `widgetDefs`, `widgetTitle`; `editor` (Task 1).
- Produces: `export function Grid({ layout, editing }: { layout: Layout; editing: boolean }): ReactNode`. In edit mode it reads and writes through `editor`, and settings open with `nav.open({ kind: "widget", id }, true)`.

- [ ] **Step 1: Implement the grid**

```tsx
// Dashboard tiles on a 12-column grid. View mode never moves anything; in
// edit mode headers drag, corners resize, and a focused tile answers the
// keyboard. Each tile has its own error boundary.
import { Component, type KeyboardEvent, type PointerEvent as ReactPointerEvent, type ReactNode, useEffect, useRef, useState } from "react";

import { nav } from "../app/nav";
import { Icon } from "../ui/Icon";
import { editor, useEditor } from "./editor";
import { COLUMNS, type Layout, ROW_HEIGHT, type Widget, moveWidget, readingOrder, resizeWidget } from "./layout";
import { widgetDefs, widgetTitle } from "./widgets";

class TileBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  override state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  override render() {
    return this.state.failed ? <div className="tile-empty"><Icon name="alert" size={18} /> This tile failed to show</div> : this.props.children;
  }
}

const GAP = 12;

export function Grid({ layout, editing }: { layout: Layout; editing: boolean }) {
  const { selected } = useEditor();
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(1200);
  useEffect(() => {
    if (!box.current) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry?.contentRect.width ?? 1200));
    observer.observe(box.current);
    return () => observer.disconnect();
  }, []);
  const phone = width < 720;
  const column = (width + GAP) / COLUMNS;
  const height = layout.widgets.reduce((max, w) => Math.max(max, w.y + w.h), 0) * ROW_HEIGHT;
  const canEdit = editing && !phone;

  const drag = (event: ReactPointerEvent, widget: Widget, mode: "move" | "resize") => {
    if (!canEdit || (mode === "move" && (event.target as HTMLElement).closest("button"))) return;
    event.preventDefault();
    editor.select(widget.id);
    const start = { x: event.clientX, y: event.clientY };
    const onMove = (move: PointerEvent) => {
      const dx = Math.round((move.clientX - start.x) / column);
      const dy = Math.round((move.clientY - start.y) / ROW_HEIGHT);
      const draft = editor.state().draft ?? layout;
      editor.change(mode === "move" ? moveWidget(draft, widget.id, widget.x + dx, widget.y + dy) : resizeWidget(draft, widget.id, widget.w + dx, widget.h + dy));
    };
    const onUp = () => { window.removeEventListener("pointermove", onMove); window.removeEventListener("pointerup", onUp); };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  };

  const onKey = (event: KeyboardEvent, widget: Widget) => {
    if (!canEdit || event.target !== event.currentTarget) return;
    const step: Record<string, [number, number]> = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
    const delta = step[event.key];
    const draft = editor.state().draft ?? layout;
    if (delta) {
      event.preventDefault();
      editor.change(event.shiftKey ? resizeWidget(draft, widget.id, widget.w + delta[0], widget.h + delta[1]) : moveWidget(draft, widget.id, widget.x + delta[0], widget.y + delta[1]));
    } else if (event.key === "Delete" || event.key === "Backspace") {
      event.preventDefault();
      editor.remove(widget.id);
    } else if (event.key === "Enter") {
      nav.open({ kind: "widget", id: widget.id }, true);
    }
  };

  const tiles = phone ? readingOrder(layout.widgets) : layout.widgets;
  return (
    <div ref={box} className={phone ? "grid grid--stacked" : canEdit ? "grid grid--editing" : "grid"} style={phone ? undefined : { height }}>
      {tiles.map((widget) => {
        const Def = widgetDefs[widget.type];
        const title = widgetTitle(widget);
        const style = phone ? undefined : {
          left: widget.x * column, top: widget.y * ROW_HEIGHT,
          width: widget.w * column - GAP, height: widget.h * ROW_HEIGHT - GAP,
        };
        return (
          <section key={widget.id} className="tile" style={style} aria-label={title} data-selected={canEdit && selected === widget.id || undefined}
            tabIndex={canEdit ? 0 : undefined} onKeyDown={(event) => onKey(event, widget)} onFocus={() => canEdit && editor.select(widget.id)}>
            <header className="tile__head" onPointerDown={(event) => drag(event, widget, "move")}>
              <h2 className="tile__title truncate">{title}</h2>
              {canEdit && (
                <span className="row">
                  <button type="button" className="icon-button" aria-label={`Settings for ${title}`} onClick={() => nav.open({ kind: "widget", id: widget.id }, true)}><Icon name="filter" size={14} /></button>
                  <button type="button" className="icon-button" aria-label={`Remove ${title}`} onClick={() => editor.remove(widget.id)}><Icon name="close" size={14} /></button>
                </span>
              )}
            </header>
            <div className="tile__body"><TileBoundary><Def.View widget={widget} /></TileBoundary></div>
            {canEdit && <span className="tile__grip" onPointerDown={(event) => drag(event, widget, "resize")} aria-hidden="true" />}
          </section>
        );
      })}
      {layout.widgets.length === 0 && <div className="tile-empty grid__empty"><Icon name="plus" size={18} /> {editing ? "Add a widget to start." : "This dashboard is empty."}</div>}
    </div>
  );
}
```

In `editor.ts`, export the snapshot getter under the name the grid uses:
add `state: () => state,` to the `editor` object. `editorState` stays for
the tests.

Styles (append to `panels.css`):

```css
.grid { position: relative; margin: 0 24px 24px; }
.grid--stacked { display: grid; gap: 12px; }
.grid--stacked .tile { position: static; min-height: 140px; }
.grid__empty { padding: 32px; justify-content: center; border: 2px dashed var(--line-strong); border-radius: var(--r-3); }
.tile {
  position: absolute; display: flex; flex-direction: column; overflow: hidden; background: var(--surface);
  border: 1px solid var(--line); border-radius: var(--r-3); box-shadow: var(--shadow-1); transition: box-shadow var(--fast), border-color var(--fast);
}
.grid--editing .tile { transition: left var(--fast), top var(--fast), width var(--fast), height var(--fast); }
.grid--editing .tile__head { cursor: grab; }
.grid--editing .tile:focus-visible, .tile[data-selected] { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); outline: none; }
.tile__head { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 10px 12px 0 14px; min-height: 36px; user-select: none; }
.tile__title { font-size: 13px; font-weight: 600; color: var(--text-2); }
.tile__body { flex: 1; min-height: 0; overflow: auto; padding: 8px 14px 12px; }
.tile__body .stat__value { font-size: 30px; }
.tile__grip { position: absolute; right: 2px; bottom: 2px; width: 14px; height: 14px; cursor: nwse-resize;
  background: linear-gradient(135deg, transparent 55%, var(--line-strong) 55%, var(--line-strong) 65%, transparent 65%, transparent 75%, var(--line-strong) 75%); }
```

- [ ] **Step 2: Typecheck and lint**

Run: `npx tsc --noEmit && npx eslint . --max-warnings 0`
Expected: no output. The grid's behaviour is tested end to end in Task 4.

- [ ] **Step 3: Commit**

```bash
git add crates/openvibes-console/web/v2/src
git commit -m "Console v2: dashboard grid (drag, resize, keyboard, phone stacking, per-tile errors)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: Dashboard view, gallery and settings panels, and wiring

**Files:**
- Create: `crates/openvibes-console/web/v2/src/dashboards/DashboardsView.tsx`
- Create: `crates/openvibes-console/web/v2/src/dashboards/panels.tsx` (`WidgetGalleryPanel`, `WidgetSettingsPanel`)
- Create: `crates/openvibes-console/web/v2/src/dashboards/attention.tsx` (move `greeting` and `useAttention` out of `views/Overview.tsx`; delete `Overview.tsx`; update `tiles.tsx` imports)
- Modify: `crates/openvibes-console/web/v2/src/app/registry.tsx`:
  - replace the Overview view with Dashboards (`path: "/"`, `prefix: "/dashboards/"`, `keys: "g d"`, `access: []`);
  - add the panels `widget-gallery` and `widget`.
- Modify: `crates/openvibes-console/web/v2/src/shell/App.tsx` (prefix matching; empty `access` means any signed-in user)
- Modify: `crates/openvibes-console/web/v2/src/shell/CommandPalette.tsx` (a "Dashboards" group)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `ViewDef` gains `prefix?: string`;
  - `canView(path)` returns `true` for a view with empty `access`;
  - the current view is `views.find((v) => v.path === view || (v.prefix !== undefined && view.startsWith(v.prefix)))`.

- [ ] **Step 1: Wire the registry, App and palette**

In `registry.tsx`, change the first entry and the type:

```tsx
export type ViewDef = {
  path: string; prefix?: string; label: string; icon: IconName; group: "Investigate" | "Operate" | "Administer";
  access: readonly { permission: Permission; global?: boolean }[]; keys: string; render: () => ReactNode;
};
// ...
  { path: "/", prefix: "/dashboards/", label: "Dashboards", icon: "overview", group: "Investigate", keys: "g d", access: [], render: () => <DashboardsView /> },
```

Add the panels:

```tsx
  "widget-gallery": { label: "Add widget", icon: "plus", title: () => "Add widget", render: () => <WidgetGalleryPanel /> },
  widget: { label: "Widget", icon: "filter", title: (id) => id, render: (id) => <WidgetSettingsPanel id={id} /> },
```

In `App.tsx`:
- `canView = (path) => { const view = views.find((v) => v.path === path); return view !== undefined && (view.access.length === 0 || view.access.some(...)); }`;
- `current = views.find((v) => v.path === view || (v.prefix !== undefined && view.startsWith(v.prefix)))`.

In `CommandPalette.tsx`, load `useResource<DashboardPage>("/api/v1/dashboards")` and add items in a "Dashboards" group:
- "Overview (built-in)" → `nav.view("/dashboards/overview")`;
- each dashboard → `nav.view(`/dashboards/${d.dashboard_id}`)`, with the hint "shared" when `!d.mine`;
- when the query is empty, list only the first 5.

- [ ] **Step 2: Implement the panels**

```tsx
// Widget gallery and per-widget settings, in the inspector beside the
// dashboard being edited.
import { nav } from "../app/nav";
import { Empty } from "../ui/bits";
import { Icon } from "../ui/Icon";
import { PanelHeader } from "../ui/panel";
import { editor, useEditor } from "./editor";
import { WIDGET_TYPES } from "./layout";
import { widgetDefs, widgetTitle } from "./widgets";

export function WidgetGalleryPanel() {
  const { draft } = useEditor();
  if (!draft) return <div className="panel-body"><Empty icon="overview" title="Not editing">Open one of your dashboards and choose Edit.</Empty></div>;
  return (
    <>
      <PanelHeader icon="plus" kind="Dashboard" title="Add widget" subtitle="Every widget shows only what your role can see, for whoever opens the dashboard." />
      <ul className="gallery">
        {WIDGET_TYPES.map((type) => {
          const def = widgetDefs[type];
          return (
            <li key={type}>
              <button type="button" className="gallery__item" onClick={() => { const id = editor.add(type); nav.open({ kind: "widget", id }, true); }}>
                <span className="attention__icon"><Icon name={def.icon} size={16} /></span>
                <span className="grow"><strong>{def.label}</strong><span className="subtle">{def.description}</span></span>
                <Icon name="plus" size={16} />
              </button>
            </li>
          );
        })}
      </ul>
    </>
  );
}

export function WidgetSettingsPanel({ id }: { id: string }) {
  const { draft } = useEditor();
  const widget = draft?.widgets.find((w) => w.id === id);
  if (!widget) return <div className="panel-body"><Empty icon="filter" title="No such widget">It was removed, or the dashboard is not being edited.</Empty></div>;
  const def = widgetDefs[widget.type];
  const title = typeof widget.config.title === "string" ? widget.config.title : "";
  return (
    <>
      <PanelHeader icon={def.icon} kind={def.label} title={widgetTitle(widget)} subtitle={def.description} />
      <div className="panel-body stack">
        <label className="field">Title<input className="input" maxLength={80} value={title} placeholder={widgetTitle({ ...widget, config: { ...widget.config, title: "" } })}
          onChange={(event) => editor.configure(id, { ...widget.config, title: event.target.value })} /></label>
        <def.Settings widget={widget} onChange={(config) => editor.configure(id, config)} />
        <div><button type="button" className="button button--danger button--small" onClick={() => { editor.remove(id); nav.closeAll(); }}><Icon name="close" size={14} /> Remove widget</button></div>
      </div>
    </>
  );
}
```

CSS: `.gallery { list-style: none; margin: 0; padding: 0 12px 12px; display: grid; gap: 6px; }`
and `.gallery__item { all: unset; display: flex; align-items: center; gap: 12px; padding: 10px; border-radius: var(--r-2); cursor: pointer; width: 100%; box-sizing: border-box; }`
with `.gallery__item:hover, .gallery__item:focus-visible { background: var(--surface-2); } .gallery__item span.grow { display: grid; }`.

- [ ] **Step 3: Implement the dashboard view**

```tsx
// Dashboards: the console's home. Shows the home dashboard at "/", any
// other at /dashboards/{id}; the built-in Overview is read-only.
import { useEffect, useState } from "react";

import { ApiError, invalidate, request, useResource } from "../api/client";
import type { AgentSummary, Dashboard, DashboardPage, HomeDashboard } from "../api/types";
import { nav, useLocation } from "../app/nav";
import { useSession } from "../app/session";
import { Empty, ErrorBox, Loading } from "../ui/bits";
import { plural } from "../ui/format";
import { Icon } from "../ui/Icon";
import { Confirm } from "../ui/panel";
import { toast } from "../ui/toast";
import { greeting } from "./attention";
import { BUILTIN_ID, BUILTIN_LAYOUT, BUILTIN_NAME } from "./builtin";
import { editor, useEditor } from "./editor";
import { Grid } from "./Grid";
import type { Layout } from "./layout";

const ROLES = ["viewer", "analyst", "operator", "admin"] as const;

export function DashboardsView() {
  const { view } = useLocation();
  const home = useResource<HomeDashboard>(view === "/" ? "/api/v1/me/home" : null);
  const id = view === "/" ? home.data === undefined ? undefined : home.data.dashboard_id ?? BUILTIN_ID : decodeURIComponent(view.slice("/dashboards/".length));
  if (view === "/" && home.loading && !home.data) return <Loading />;
  return <DashboardById id={id ?? BUILTIN_ID} />;
}

function DashboardById({ id }: { id: string }) {
  const builtin = id === BUILTIN_ID;
  const stored = useResource<Dashboard>(builtin ? null : `/api/v1/dashboards/${encodeURIComponent(id)}`);
  const state = useEditor();
  useEffect(() => () => editor.cancel(), [id]);
  useEffect(() => {
    if (!state.dirty) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [state.dirty]);
  if (!builtin && stored.error) {
    return (
      <div className="view view-pad">
        {stored.error.status === 404
          ? <Empty icon="overview" title="This dashboard is gone">It was deleted, or it is no longer shared with you. <button type="button" className="link-button" onClick={() => nav.view("/")}>Go home</button></Empty>
          : <ErrorBox error={stored.error} />}
      </div>
    );
  }
  if (!builtin && !stored.data) return <Loading />;
  const dashboard = stored.data;
  const editing = state.draft !== null && state.dashboard?.dashboard_id === dashboard?.dashboard_id;
  const layout: Layout = editing && state.draft ? state.draft : builtin ? BUILTIN_LAYOUT : (dashboard?.layout as Layout);
  return (
    <div className="view">
      <Header dashboard={dashboard} builtin={builtin} editing={editing} />
      {editing && state.conflict && (
        <div className="view-note" role="alert">
          <Icon name="alert" size={14} /> Someone saved this dashboard since you opened it.
          <button type="button" className="button button--small" onClick={() => void editor.reloadTheirs()}>Reload theirs</button>
          <button type="button" className="button button--small" onClick={() => void editor.saveAsCopy().then((copy) => copy && nav.view(`/dashboards/${copy.dashboard_id}`))}>Save as a copy</button>
        </div>
      )}
      {editing && state.problems.length > 0 && (
        <ul className="view-note" role="alert">{state.problems.map((p) => <li key={p.field + p.code}><code>{p.field}</code>: {p.message}</li>)}</ul>
      )}
      <Grid layout={layout} editing={editing} />
    </div>
  );
}

function Header({ dashboard, builtin, editing }: { dashboard: Dashboard | undefined; builtin: boolean; editing: boolean }) {
  const { session, can } = useSession();
  const state = useEditor();
  const home = useResource<HomeDashboard>("/api/v1/me/home");
  const agents = useResource<AgentSummary>(builtin && can("agents.read") ? "/api/v1/agents/summary" : null);
  const [menu, setMenu] = useState(false);
  const id = builtin ? null : dashboard?.dashboard_id ?? null;
  const isHome = (home.data?.dashboard_id ?? null) === id;
  const mine = dashboard?.mine === true;
  const name = session?.principal.display_name.split(" ")[0];

  const duplicate = async () => {
    const copy = await request<Dashboard>("POST", "/api/v1/dashboards", { name: `Copy of ${builtin ? BUILTIN_NAME : dashboard?.name ?? ""}`.slice(0, 80), layout: builtin ? BUILTIN_LAYOUT : dashboard?.layout });
    invalidate("/api/v1/dashboards");
    nav.view(`/dashboards/${copy.dashboard_id}`);
    editor.begin(copy);
  };
  const setHome = async () => {
    await request("PUT", "/api/v1/me/home", { dashboard_id: id });
    invalidate("/api/v1/me/home");
    toast(isHome ? "Home unchanged" : "Set as home");
  };
  const share = async (roleId: string | null) => {
    if (!dashboard) return;
    await request("PUT", `/api/v1/dashboards/${dashboard.dashboard_id}/sharing`, { role_id: roleId });
    invalidate("/api/v1/dashboards");
    toast(roleId ? `Shared with ${roleId}` : "No longer shared");
  };
  const fail = (error: unknown) => toast(error instanceof ApiError ? error.message : "That did not work", true);

  return (
    <header className="view-header dashboard-header">
      <div className="view-header__top">
        <div className="view-header__title">
          {editing ? (
            <input className="input dashboard-name" aria-label="Dashboard name" value={state.name} onChange={(e) => editor.rename(e.target.value)} maxLength={80} />
          ) : builtin ? (
            <div><h1>{greeting()}{name ? `, ${name}` : ""}</h1>
              {agents.data && <p className="muted">{plural(agents.data.active, "host")} reporting{agents.data.stale > 0 ? `, ${agents.data.stale} stale` : ""}.</p>}</div>
          ) : (
            <div><h1>{dashboard?.name}</h1>{!mine && <p className="muted">Shared by {dashboard?.owner_display_name}{dashboard?.shared_role_id ? ` with ${dashboard.shared_role_id}` : ""}</p>}
              {mine && dashboard?.shared_role_id && <p className="muted">Shared with {dashboard.shared_role_id}</p>}</div>
          )}
        </div>
        <div className="row row--wrap">
          <DashboardSwitcher current={id} />
          {!editing && (
            <button type="button" className="icon-button" aria-pressed={isHome} aria-label={isHome ? "This is your home dashboard" : "Set as home"} title="Home dashboard"
              onClick={() => void setHome().catch(fail)}><Icon name="pin" size={16} /></button>
          )}
          {editing ? (
            <>
              <button type="button" className="button" onClick={() => nav.open({ kind: "widget-gallery", id: "new" }, true)}><Icon name="plus" size={15} /> Add widget</button>
              <button type="button" className="button button--ghost" onClick={() => { if (!state.dirty || window.confirm("Discard your changes?")) { editor.cancel(); nav.closeAll(); } }}>Cancel</button>
              <button type="button" className="button button--primary" disabled={state.saving} onClick={() => void editor.save().then((saved) => { if (saved) { invalidate(`/api/v1/dashboards/${saved.dashboard_id}`); nav.closeAll(); toast("Dashboard saved"); } })}>
                {state.saving ? "Saving…" : "Save"}</button>
            </>
          ) : mine && dashboard ? (
            <button type="button" className="button" onClick={() => editor.begin(dashboard)}><Icon name="filter" size={15} /> Edit</button>
          ) : (
            <button type="button" className="button" onClick={() => void duplicate().catch(fail)}><Icon name="copy" size={15} /> Duplicate to edit</button>
          )}
          {!editing && (
            <div className="menu">
              <button type="button" className="icon-button" aria-haspopup="menu" aria-expanded={menu} aria-label="Dashboard menu" onClick={() => setMenu((m) => !m)}><Icon name="chevronDown" size={16} /></button>
              {menu && (
                <div className="menu__pop" role="menu" onClick={() => setMenu(false)}>
                  <button type="button" role="menuitem" className="menu__item" onClick={() => void duplicate().catch(fail)}><Icon name="copy" size={14} /> Duplicate</button>
                  {mine && dashboard && <button type="button" role="menuitem" className="menu__item" onClick={() => { editor.begin(dashboard); setTimeout(() => document.querySelector<HTMLInputElement>(".dashboard-name")?.select(), 0); }}><Icon name="filter" size={14} /> Rename</button>}
                  {mine && can("dashboards.share", true) && (
                    <div className="menu__section">
                      <div className="section-title">Share with role</div>
                      {[null, ...ROLES].map((role) => (
                        <button key={role ?? "none"} type="button" role="menuitemradio" aria-checked={(dashboard?.shared_role_id ?? null) === role} className="menu__item"
                          onClick={() => void share(role).catch(fail)}>{(dashboard?.shared_role_id ?? null) === role ? <Icon name="check" size={14} /> : <span style={{ width: 14 }} />} {role ?? "Not shared"}</button>
                      ))}
                    </div>
                  )}
                  {mine && dashboard && (
                    <Confirm danger label={`Delete "${dashboard.name}"? People it is shared with lose it too.`} onConfirm={async () => {
                      await request("DELETE", `/api/v1/dashboards/${dashboard.dashboard_id}`);
                      invalidate("/api/v1/dashboards");
                      invalidate("/api/v1/me/home");
                      nav.view("/");
                      toast("Dashboard deleted");
                    }}><Icon name="close" size={14} /> Delete</Confirm>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

function DashboardSwitcher({ current }: { current: string | null }) {
  const list = useResource<DashboardPage>("/api/v1/dashboards");
  const [open, setOpen] = useState(false);
  const items = list.data?.items ?? [];
  const go = (target: string) => {
    if (editor.state().dirty && !window.confirm("Leave without saving your changes?")) return;
    editor.cancel();
    nav.view(`/dashboards/${target}`);
  };
  const create = async () => {
    const created = await request<Dashboard>("POST", "/api/v1/dashboards", { name: "Untitled dashboard", layout: { schema: 1, widgets: [] } });
    invalidate("/api/v1/dashboards");
    go(created.dashboard_id);
    editor.begin(created);
    nav.open({ kind: "widget-gallery", id: "new" }, true);
  };
  const group = (label: string, rows: Dashboard[]) => rows.length > 0 && (
    <div className="menu__section"><div className="section-title">{label}</div>
      {rows.map((d) => <button key={d.dashboard_id} type="button" role="menuitemradio" aria-checked={current === d.dashboard_id} className="menu__item" onClick={() => go(d.dashboard_id)}>{d.name}</button>)}</div>
  );
  return (
    <div className="menu">
      <button type="button" className="button" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((o) => !o)}><Icon name="overview" size={15} /> Dashboards <Icon name="chevronDown" size={14} /></button>
      {open && (
        <div className="menu__pop" role="menu" onClick={() => setOpen(false)}>
          <div className="menu__section"><div className="section-title">Built-in</div>
            <button type="button" role="menuitemradio" aria-checked={current === null} className="menu__item" onClick={() => go(BUILTIN_ID)}>{BUILTIN_NAME}</button></div>
          {group("Mine", items.filter((d) => d.mine))}
          {group("Shared with me", items.filter((d) => !d.mine))}
          <button type="button" role="menuitem" className="menu__item" onClick={() => void create().catch((error: unknown) => toast(error instanceof ApiError ? error.message : "Could not create", true))}>
            <Icon name="plus" size={14} /> New dashboard</button>
        </div>
      )}
    </div>
  );
}
```

CSS: `.dashboard-name { font-size: 20px; font-weight: 600; height: 40px; width: min(420px, 100%); }`.

Move `greeting()` and `useAttention()` (with `AttentionItem`) from
`views/Overview.tsx` into `dashboards/attention.tsx` unchanged, delete
`views/Overview.tsx`, and update the import in `tiles.tsx`.

**Leaving the page while dirty (Review Focus 1).** The rail and palette
call `nav.view`, which is bypassed by the `DashboardSwitcher`'s `go`.
Guard it in one place: in `app/nav.ts`, add a hook `nav.guard(check:
() => boolean)` that `view()` consults before navigating:

```ts
let guard: (() => boolean) | null = null;
// in nav:
  guard(check: (() => boolean) | null) { guard = check; },
// at the start of view(view, params):
    if (guard && !guard()) return;
```

In `DashboardById`, register
`nav.guard(() => !editor.state().dirty || window.confirm("Leave without saving your changes?"))`
in an effect on `state.dirty`, and clear it (`nav.guard(null)`) on
cleanup.

- [ ] **Step 4: Typecheck, lint, unit-test, then fix the existing Playwright tests**

Run: `npx tsc --noEmit && npx eslint . --max-warnings 0 && npx vitest run --config vite.v2.config.ts 2>&1 | grep -E "Tests |×"`
Expected: clean, and all unit tests pass.

In `v2/e2e/smoke.spec.ts`, the rail link "Overview" is now "Dashboards".
No existing test clicks it by name. Run the suite to find any other
references:

Run: `npx playwright test --config playwright.v2.config.ts --project chromium --reporter=line 2>&1 | tail -4`
Expected: 19 passed. The greeting `h1` still contains "Alex", and the
attention rows still use `.attention__row`.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-console/web/v2/src
git commit -m "Console v2: dashboards are home (switcher, edit, save, share, home, built-in Overview)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: End-to-end tests, accessibility, docs and a live check

**Files:**
- Create: `crates/openvibes-console/web/v2/e2e/dashboards.spec.ts`
- Modify: `docs/components/console-v2.md` (dashboards section), `docs/components/console-dashboards.md` (UI section)

- [ ] **Step 1: Write the end-to-end tests**

```ts
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
  await page.mouse.move(900, 500);
});

test("home falls back to the built-in", async ({ page }) => {
  await expect(page.locator(".tile")).toHaveCount(9);
  await expect(page.getByRole("button", { name: "Duplicate to edit" })).toBeVisible();
});

test("a new dashboard gets a widget, is saved, and survives a reload", async ({ page }) => {
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await page.getByRole("button", { name: /^Number/ }).click();
  await page.getByLabel("Count").selectOption("agents.stale");
  await page.getByLabel("Dashboard name").fill("Stale watch");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Stale watch");
  const url = page.url();
  await page.reload();
  await expect(page).toHaveURL(url);
  await expect(page.locator(".tile", { hasText: "Stale hosts" })).toBeVisible();
});

test("the built-in is duplicated to edit, a tile moves by keyboard, and it becomes home", async ({ page }) => {
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Copy of Overview");
  const tile = page.locator(".tile").first();
  const before = await tile.evaluate((el) => (el as HTMLElement).style.top);
  await tile.focus();
  await page.keyboard.press("ArrowDown");
  await expect.poll(async () => tile.evaluate((el) => (el as HTMLElement).style.top)).not.toBe(before);
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByRole("button", { name: "Set as home" }).click();
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Copy of Overview");
});

test("asks before leaving unsaved edits", async ({ page }) => {
  await page.getByRole("button", { name: "Duplicate to edit" }).click();
  await page.getByLabel("Dashboard name").fill("Changed");
  let asked = false;
  page.once("dialog", (dialog) => { asked = true; void dialog.dismiss(); });
  await page.getByRole("link", { name: "Findings" }).click();
  expect(asked).toBe(true);
  await expect(page.getByLabel("Dashboard name")).toHaveValue("Changed");
});

test("an analyst sees the team dashboard read-only", async ({ page }) => {
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "analyst" }).click();
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitemradio", { name: "Analyst triage" }).click();
  await expect(page.getByText("Shared by")).toBeVisible();
  await expect(page.getByRole("button", { name: "Edit" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Duplicate to edit" })).toBeVisible();
});

test("an admin shares a dashboard with a role", async ({ page }) => {
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitemradio", { name: "My morning check" }).click();
  await page.getByRole("button", { name: "Dashboard menu" }).click();
  await page.getByRole("menuitemradio", { name: "analyst" }).click();
  await expect(page.getByText("Shared with analyst")).toBeVisible();
});

for (const scheme of ["light", "dark"] as const) {
  test(`no accessibility violations on a dashboard, viewing and editing (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto("/dashboards/d-admin-morning");
    await expect(page.locator(".tile").first()).toBeVisible();
    await page.waitForTimeout(400);
    expect((await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id)).toEqual([]);
    await page.getByRole("button", { name: "Edit" }).click();
    await page.getByRole("button", { name: "Add widget" }).click();
    await page.waitForTimeout(300);
    expect((await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id)).toEqual([]);
  });
}
```

- [ ] **Step 2: Run them, and fix what fails before going on**

Run: `npx playwright test --config playwright.v2.config.ts --reporter=line 2>&1 | tail -6`
Expected: all pass in Chromium and Firefox: 19 existing + 8 new = 27 per browser.
For an axe colour-contrast failure, fix the token or style it names
(as for v2's `--text-3`), not the test.

- [ ] **Step 3: Update the docs**

- `docs/components/console-v2.md`: a "Dashboards" section. Home is the
  built-in Overview until you choose another. Cover the switcher, edit
  mode (drag, resize, keyboard), the widget types, saving and conflicts,
  sharing and home, and link `console-dashboards.md`.
- `docs/components/console-dashboards.md`: add a "User interface"
  section with the same points, and the test commands for the UI:
  `npx vitest run --config vite.v2.config.ts src/dashboards` and
  `npx playwright test --config playwright.v2.config.ts dashboards`.

- [ ] **Step 4: Live check against a real console**

Using the same harness as v2's live test:
1. Start a throwaway database (`scripts/test-db.sh`) and run
   `openvibes-admin migrate` and `user create` for `alex` (admin) and
   `sam` (analyst).
2. Run `openvibes-console` with `public_origin = "http://127.0.0.1:5174"`.
3. Run `V2_LIVE=http://127.0.0.1:<port> npm run dev:v2` and open
   `/?live=1`.

As alex:
- create a dashboard, add a Number and a Note, and save;
- edit it in a second tab, then save in the first to see the conflict
  banner;
- share it with `analyst`;
- set it as home.

As sam (a second browser context):
- the dashboard is listed under "Shared with me" and is read-only;
- sam can set it as home;
- after alex stops sharing it, sam's `/` shows the built-in.

Expected: no failed API calls except the expected 412.

- [ ] **Step 5: Run the full gate and commit**

Run the Global Constraints gate. Expected: every command green.

```bash
git add crates/openvibes-console/web/v2 docs/components
git commit -m "Console v2: dashboard end-to-end and accessibility tests; docs

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

Then push and open the part-3 PR.
