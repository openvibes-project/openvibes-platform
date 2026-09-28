# Console Dashboards, part 3a of 3: Grid Logic and Widgets Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pieces a dashboard is made of: grid placement rules,
the built-in Overview layout, list data shared between list views and
list tiles, and the seven widget types with their settings forms.

**Architecture:**
- Pure grid functions extend `v2/src/dashboards/layout.ts`.
- The list views (Findings, Vulnerabilities, Agents, Audit) export
  row-selection hooks, so a List tile shows exactly what the view would
  show for the same query.
- Widgets are declared in one registry, `v2/src/dashboards/widgets.ts`,
  like views and panels in `app/registry.tsx`.

**Tech Stack:** React 19, TypeScript, Vitest.

**Spec:** `docs/superpowers/specs/2026-09-28-console-dashboards-design.md`
(§2). It depends on parts 1 and 2. Part 3b builds the editor and the
view on top of this.

## Global Constraints

- The grid has 12 columns and a 56 px row height. Tiles stack in one
  column below 720 px, in reading order (`y`, then `x`).
- **Positions and sizes:** `x` 0–11, `w` 1–12, `x+w ≤ 12`, `y` 0–199,
  `h` 1–12. Every grid function returns a layout that passes
  `validateLayout`.
- **Widget configs (spec §2):**

  | type | config |
  |---|---|
  | `number` | `metric` ∈ `agents.active agents.stale agents.revoked findings.open.critical findings.open.high findings.open.medium findings.open.low vulns.exploited vulns.reboot_hosts vulns.no_fix` |
  | `breakdown` | `source` ∈ `findings vulnerabilities agents` |
  | `attention` | `include` ⊆ `exploited findings stale`; `limit` 1–20 |
  | `list` | `view` ∈ `/findings /vulnerabilities /agents /audit`; `query` (URL query string); `limit` 1–20 |
  | `trend` | `finding` (`rule_set/rule`); `days` ∈ 7, 14, 30 |
  | `top-hosts` | `limit` 1–10 |
  | `note` | `text`: string[] (≤ 16 lines, each ≤ 256 characters) |

  Every type also accepts an optional `title` string.
- A note renders as plain text; only whole `https://…` words become
  links, which show the full URL (`rel="noreferrer noopener"`,
  `target="_blank"`). No HTML or markdown is interpreted.
- Tile data loads through the existing hooks and endpoints, with the
  viewer's own permissions. A tile whose permission is missing shows "Not
  available with your role".
- **Gate (from `crates/openvibes-console/web`):**
  - `npx vitest run --config vite.v2.config.ts`;
  - `npx eslint . --max-warnings 0`;
  - `npx tsc --noEmit`.
- **Commits** end with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Dragging a tile onto another must never leave two tiles
   overlapping,** even when the pushed tile then hits a third.
   `moveWidget` with a chain of three is tested in Task 1
   (`pushes a chain of tiles down`).
2. **A tile moved past the right edge snaps inside** (`x + w ≤ 12`) and
   the layout stays valid. Tested in Task 1 (`clamps into the grid`).
3. **A note containing `javascript:alert(1)` or `<b>` is shown
   literally,** never as a link or markup. Tested in Task 3
   (`noteParts`).
4. **A List tile with an unknown `view` or a garbage query** shows "This
   list is not available" instead of crashing. Tested in Task 3
   (`parseListConfig`).
5. **A widget config written by a newer console** (unknown keys, wrong
   types) falls back to defaults instead of crashing. Tested in Task 3
   (`reads configs defensively`).

---

### Task 1: Grid placement functions

**Files:**
- Modify: `crates/openvibes-console/web/v2/src/dashboards/layout.ts`
- Test: `crates/openvibes-console/web/v2/src/dashboards/grid.test.ts`

**Interfaces:**
- Consumes: `Layout`, `Widget`, `WidgetType`, `validateLayout` (part 2).
- Produces:
  - `export const COLUMNS = 12; export const ROW_HEIGHT = 56;`
  - `export function overlaps(a: Widget, b: Widget): boolean`
  - `export function settle(widgets: readonly Widget[], fixedId: string): Widget[]`: keeps `fixedId` where it is and pushes colliding tiles down; input order preserved
  - `export function moveWidget(layout: Layout, id: string, x: number, y: number): Layout`
  - `export function resizeWidget(layout: Layout, id: string, w: number, h: number): Layout`
  - `export function addWidget(layout: Layout, type: WidgetType, size: { w: number; h: number }, config: Widget["config"]): { layout: Layout; id: string }`: placed at the bottom-left
  - `export function removeWidget(layout: Layout, id: string): Layout`
  - `export function readingOrder(widgets: readonly Widget[]): Widget[]`

- [ ] **Step 1: Write the failing tests**

```ts
import { describe, expect, it } from "vitest";

import { type Layout, addWidget, moveWidget, overlaps, readingOrder, removeWidget, resizeWidget, validateLayout } from "./layout";

const tile = (id: string, x: number, y: number, w = 4, h = 2) => ({ id, type: "number" as const, x, y, w, h, config: {} });
const at = (layout: Layout, id: string) => layout.widgets.find((w) => w.id === id);
const noOverlap = (layout: Layout) => layout.widgets.every((a) => layout.widgets.every((b) => a === b || !overlaps(a, b)));

describe("grid", () => {
  it("moves a tile and pushes the one it lands on down", () => {
    const layout: Layout = { schema: 1, widgets: [tile("a", 0, 0), tile("b", 4, 0)] };
    const moved = moveWidget(layout, "a", 4, 0);
    expect(at(moved, "a")).toMatchObject({ x: 4, y: 0 });
    expect(at(moved, "b")).toMatchObject({ x: 4, y: 2 });
    expect(noOverlap(moved)).toBe(true);
  });

  it("pushes a chain of tiles down", () => {
    const layout: Layout = { schema: 1, widgets: [tile("a", 0, 4), tile("b", 0, 0), tile("c", 0, 2)] };
    const moved = moveWidget(layout, "a", 0, 0);
    expect([at(moved, "a")?.y, at(moved, "b")?.y, at(moved, "c")?.y]).toEqual([0, 2, 4]);
    expect(noOverlap(moved)).toBe(true);
  });

  it("clamps into the grid", () => {
    const layout: Layout = { schema: 1, widgets: [tile("a", 0, 0)] };
    expect(at(moveWidget(layout, "a", 11, -3), "a")).toMatchObject({ x: 8, y: 0 });
    expect(at(resizeWidget(layout, "a", 20, 0), "a")).toMatchObject({ w: 12, h: 1 });
    expect(validateLayout(moveWidget(layout, "a", 99, 999))).toEqual([]);
  });

  it("resizing pushes tiles below out of the way", () => {
    const layout: Layout = { schema: 1, widgets: [tile("a", 0, 0), tile("b", 0, 2)] };
    const resized = resizeWidget(layout, "a", 4, 5);
    expect(at(resized, "b")?.y).toBe(5);
  });

  it("adds at the bottom with a unique id and removes", () => {
    const layout: Layout = { schema: 1, widgets: [tile("number-1", 0, 0, 4, 3)] };
    const { layout: added, id } = addWidget(layout, "number", { w: 3, h: 2 }, { metric: "agents.active" });
    expect(id).toBe("number-2");
    expect(at(added, id)).toMatchObject({ x: 0, y: 3, w: 3, h: 2 });
    expect(removeWidget(added, id).widgets).toHaveLength(1);
  });

  it("reads tiles row by row for phones", () => {
    expect(readingOrder([tile("c", 0, 4), tile("b", 6, 0), tile("a", 0, 0)]).map((w) => w.id)).toEqual(["a", "b", "c"]);
  });
});
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `npx vitest run --config vite.v2.config.ts src/dashboards/grid`
Expected: FAIL, "moveWidget is not exported".

- [ ] **Step 3: Implement (append to `layout.ts`)**

```ts
export const COLUMNS = 12;
export const ROW_HEIGHT = 56;
const clamp = (value: number, low: number, high: number) => Math.min(high, Math.max(low, Math.round(value)));

export function overlaps(a: Widget, b: Widget): boolean {
  return a.id !== b.id && a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

/** Keeps `fixedId` in place and moves every colliding tile straight down,
 *  top to bottom, so no two tiles overlap. Input order is preserved. */
export function settle(widgets: readonly Widget[], fixedId: string): Widget[] {
  const fixed = widgets.find((w) => w.id === fixedId);
  if (!fixed) return [...widgets];
  const placed: Widget[] = [fixed];
  const others = widgets.filter((w) => w.id !== fixedId).sort((a, b) => a.y - b.y || a.x - b.x);
  const moved = new Map<string, Widget>([[fixed.id, fixed]]);
  for (const widget of others) {
    let candidate = widget;
    while (placed.some((p) => overlaps(candidate, p)) && candidate.y < 199) candidate = { ...candidate, y: candidate.y + 1 };
    placed.push(candidate);
    moved.set(candidate.id, candidate);
  }
  return widgets.map((w) => moved.get(w.id) ?? w);
}

export function moveWidget(layout: Layout, id: string, x: number, y: number): Layout {
  const widgets = layout.widgets.map((w) => w.id === id ? { ...w, x: clamp(x, 0, COLUMNS - w.w), y: clamp(y, 0, 199) } : w);
  return { ...layout, widgets: settle(widgets, id) };
}

export function resizeWidget(layout: Layout, id: string, w: number, h: number): Layout {
  const widgets = layout.widgets.map((widget) => widget.id === id ? { ...widget, w: clamp(w, 1, COLUMNS - widget.x), h: clamp(h, 1, 12) } : widget);
  return { ...layout, widgets: settle(widgets, id) };
}

export function addWidget(layout: Layout, type: WidgetType, size: { w: number; h: number }, config: Widget["config"]): { layout: Layout; id: string } {
  let n = 1;
  while (layout.widgets.some((w) => w.id === `${type}-${n}`)) n += 1;
  const id = `${type}-${n}`;
  const bottom = layout.widgets.reduce((max, w) => Math.max(max, w.y + w.h), 0);
  const widget: Widget = { id, type, x: 0, y: Math.min(bottom, 199), w: Math.min(size.w, COLUMNS), h: size.h, config };
  return { layout: { ...layout, widgets: [...layout.widgets, widget] }, id };
}

export function removeWidget(layout: Layout, id: string): Layout {
  return { ...layout, widgets: layout.widgets.filter((w) => w.id !== id) };
}

export function readingOrder(widgets: readonly Widget[]): Widget[] {
  return [...widgets].sort((a, b) => a.y - b.y || a.x - b.x);
}
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `npx vitest run --config vite.v2.config.ts src/dashboards`
Expected: PASS (grid 6, layout 5).

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-console/web/v2/src/dashboards
git commit -m "Console v2: dashboard grid placement (move, resize, push down, phone order)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: List rows shared by list views and List tiles

**Files:**
- Create: `crates/openvibes-console/web/v2/src/views/rows.ts`
- Modify: `views/Findings.tsx`, `views/Vulnerabilities.tsx`, `views/Agents.tsx`, `views/Admin.tsx` (`Audit`) to use the hooks
- Test: `crates/openvibes-console/web/v2/src/views/rows.test.ts`

**Interfaces:**
- Produces:
  - `export type ListView = "/findings" | "/vulnerabilities" | "/agents" | "/audit";`
  - `export const LIST_VIEWS: readonly ListView[]`
  - `export function selectFindings(all: readonly FindingGroup[], params: URLSearchParams): FindingGroup[]`
  - `export function selectAgents(all: readonly Agent[], params: URLSearchParams): Agent[]`
  - `export function selectAdvisories(all: readonly AdvisoryRow[], params: URLSearchParams): AdvisoryRow[]` (`AdvisoryRow` and `groupByAdvisory` move here from `Vulnerabilities.tsx`)
  - `export function selectAudit(all: readonly AuditEvent[], params: URLSearchParams): AuditEvent[]`
  - `export function vulnerabilityQuery(params: URLSearchParams): string`: the API path with the server-side filters
  - `export function useListRows(view: ListView, params: URLSearchParams): { rows: ListRow[]; total: number; loading: boolean; error: ApiError | undefined }`, where `type ListRow = { key: string; open: PanelRef; title: string; meta: string; badge: { label: string; tone: string } }`

- [ ] **Step 1: Write the failing tests**

```ts
import { describe, expect, it } from "vitest";

import { selectAgents, selectAudit, selectFindings } from "./rows";

const group = (rule: string, severity: "critical" | "low", open: number) => ({
  rule_set_id: "s", rule_id: rule, severity, latest_message: `msg ${rule}`, endpoint_count: open + 1, older_endpoint_count: 0,
  rule_versions: [1], first_observed_at: "2026-09-01T00:00:00Z", last_observed_at: "2026-09-02T00:00:00Z",
  triage_counts: { open, investigating: 0, mitigated: 1, accepted_risk: 0, false_positive: 0 },
});

describe("list selection matches the views", () => {
  it("findings: open only by default, severity and text filters", () => {
    const all = [group("A", "critical", 2), group("B", "low", 0)];
    expect(selectFindings(all, new URLSearchParams()).map((g) => g.rule_id)).toEqual(["A"]);
    expect(selectFindings(all, new URLSearchParams("state=all")).map((g) => g.rule_id)).toEqual(["A", "B"]);
    expect(selectFindings(all, new URLSearchParams("state=all&severity=low")).map((g) => g.rule_id)).toEqual(["B"]);
    expect(selectFindings(all, new URLSearchParams("state=all&q=msg%20b")).map((g) => g.rule_id)).toEqual(["B"]);
  });

  it("agents: status and text", () => {
    const agent = (id: string, status: "active" | "stale") => ({ id, hostname: `${id}.example.test`, status, enrolled_at: "", capabilities: [] });
    const all = [agent("web", "active"), agent("db", "stale")];
    expect(selectAgents(all, new URLSearchParams("status=stale")).map((a) => a.id)).toEqual(["db"]);
    expect(selectAgents(all, new URLSearchParams("q=web")).map((a) => a.id)).toEqual(["web"]);
  });

  it("audit: failures filter", () => {
    const event = (id: string, result: string) => ({ id, action: "user.login", actor: "a", at: "2026-09-01T00:00:00Z", result });
    expect(selectAudit([event("1", "success"), event("2", "failure")], new URLSearchParams("result=failure")).map((e) => e.id)).toEqual(["2"]);
  });
});
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `npx vitest run --config vite.v2.config.ts src/views/rows`
Expected: FAIL, "Cannot find module './rows'".

- [ ] **Step 3: Implement `rows.ts` by moving the views' filtering into it**

```ts
// What each list view shows for a query, in one place: the views and the
// dashboard List tile both use it, so a tile always matches its view.
import { useMemo } from "react";

import { type ApiError, useAllPages, useResource } from "../api/client";
import type { Agent, AuditEvent, FindingGroup, Vulnerability, VulnerabilityPage } from "../api/types";
import type { PanelRef } from "../app/location";
import { auditSince, severityOrder } from "../ui/format";
import { matches } from "../ui/table";

export const LIST_VIEWS = ["/findings", "/vulnerabilities", "/agents", "/audit"] as const;
export type ListView = (typeof LIST_VIEWS)[number];
export type ListRow = { key: string; open: PanelRef; title: string; meta: string; badge: { label: string; tone: string } };

export type AdvisoryRow = {
  id: string; title: string; severity: string; cves: string[]; cvss: number | null; epss: number | null;
  exploited: boolean; kev: boolean; ransomware: boolean; hosts: number; reboot: number; noFix: boolean;
};

export function groupByAdvisory(items: readonly Vulnerability[]): AdvisoryRow[] {
  // (moved unchanged from views/Vulnerabilities.tsx)
}

export function selectFindings(all: readonly FindingGroup[], params: URLSearchParams): FindingGroup[] {
  const severity = params.get("severity");
  const onlyOpen = params.get("state") !== "all";
  const ruleSet = params.get("set");
  const q = params.get("q") ?? "";
  return all.filter((g) => (!severity || g.severity === severity) && (!onlyOpen || g.triage_counts.open > 0)
    && (!ruleSet || g.rule_set_id === ruleSet) && matches([g.latest_message, g.rule_id, g.rule_set_id], q));
}

export function selectAgents(all: readonly Agent[], params: URLSearchParams): Agent[] {
  const status = params.get("status");
  const q = params.get("q") ?? "";
  return all.filter((a) => (!status || a.status === status) && matches([a.hostname, a.id, a.scanner_version], q));
}

export function vulnerabilityQuery(params: URLSearchParams): string {
  const query = new URLSearchParams();
  if (params.get("exploited") === "true") query.set("exploited", "true");
  if (params.get("reboot") === "true") query.set("reboot_needed", "true");
  const severity = params.get("severity");
  if (severity) query.set("severity", severity);
  return `/api/v1/vulnerabilities${query.size ? `?${query}` : ""}`;
}

export function selectAdvisories(all: readonly AdvisoryRow[], params: URLSearchParams): AdvisoryRow[] {
  const q = params.get("q") ?? "";
  return all.filter((row) => (params.get("nofix") !== "true" || row.noFix) && matches([row.title, row.id, ...row.cves], q));
}

export function selectAudit(all: readonly AuditEvent[], params: URLSearchParams): AuditEvent[] {
  const failed = params.get("result") === "failure";
  return all.filter((e) => (!failed || e.result !== "success") && matches([e.action, e.actor, e.target], params.get("q") ?? ""));
}

const sev = (s: string) => severityOrder[s] ?? 9;

/** The first rows of a list view for a query, ready for a compact list. */
export function useListRows(view: ListView, params: URLSearchParams): { rows: ListRow[]; total: number; loading: boolean; error: ApiError | undefined } {
  const groups = useAllPages<FindingGroup>(view === "/findings" ? "/api/v1/findings/groups" : null);
  const agents = useAllPages<Agent>(view === "/agents" ? "/api/v1/agents" : null);
  const vulns = useResource<VulnerabilityPage>(view === "/vulnerabilities" ? vulnerabilityQuery(params) : null);
  const audit = useAllPages<AuditEvent>(view === "/audit" ? `/api/v1/audit-events?since=${encodeURIComponent(auditSince(params))}` : null, 1000);
  return useMemo(() => {
    const status = view === "/findings" ? groups : view === "/agents" ? agents : view === "/audit" ? audit : vulns;
    let rows: ListRow[] = [];
    if (view === "/findings") {
      rows = selectFindings(groups.data ?? [], params).sort((a, b) => sev(a.severity) - sev(b.severity) || b.triage_counts.open - a.triage_counts.open)
        .map((g) => ({ key: `${g.rule_set_id}/${g.rule_id}`, open: { kind: "finding", id: `${g.rule_set_id}/${g.rule_id}` }, title: g.latest_message,
          meta: `${g.rule_id} · ${g.triage_counts.open} open`, badge: { label: g.severity, tone: g.severity } }));
    } else if (view === "/agents") {
      rows = selectAgents(agents.data ?? [], params).map((a) => ({ key: a.id, open: { kind: "agent", id: a.id }, title: a.hostname ?? a.id,
        meta: a.id, badge: { label: a.status, tone: a.status === "active" ? "ok" : a.status === "stale" ? "warn" : a.status === "revoked" ? "bad" : "info" } }));
    } else if (view === "/audit") {
      rows = selectAudit(audit.data ?? [], params).sort((a, b) => b.at.localeCompare(a.at)).map((e) => ({ key: e.id, open: { kind: "audit-event", id: e.id },
        title: e.action, meta: `${e.actor} · ${e.target ?? ""}`, badge: { label: e.result, tone: e.result === "success" ? "ok" : "bad" } }));
    } else {
      rows = selectAdvisories(groupByAdvisory(vulns.data?.items ?? []), params)
        .sort((a, b) => Number(b.exploited) - Number(a.exploited) || sev(a.severity) - sev(b.severity) || (b.epss ?? 0) - (a.epss ?? 0))
        .map((r) => ({ key: r.id, open: { kind: "advisory", id: r.id }, title: r.title, meta: `${r.hosts} hosts${r.exploited ? " · exploited" : ""}`,
          badge: { label: r.severity, tone: r.severity } }));
    }
    const data = "data" in status ? status.data : undefined;
    return { rows, total: rows.length, loading: status.loading && data === undefined, error: status.error };
  }, [view, params, groups, agents, vulns, audit]);
}
```

(The `groupByAdvisory` body is the existing code from
`views/Vulnerabilities.tsx`, moved without changes.)

Then change the views to use the selectors:
- `Findings.tsx`: replace the inline `rows` `useMemo` filter with `useMemo(() => selectFindings(all, params), [all, params])`.
- `Agents.tsx`: use `selectAgents`.
- `Vulnerabilities.tsx`: import `groupByAdvisory`, `selectAdvisories` and `vulnerabilityQuery` from `./rows`, delete its own copies, and build its `useResource` path with `vulnerabilityQuery(params)`.
- `Admin.tsx` `Audit`: use `selectAudit`.

- [ ] **Step 4: Run all tests, including the e2e smoke, to prove the views are unchanged**

Run: `npx vitest run --config vite.v2.config.ts && npx playwright test --config playwright.v2.config.ts --project chromium --reporter=line 2>&1 | tail -2`
Expected: vitest all pass (3 new), Playwright 19 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-console/web/v2/src/views
git commit -m "Console v2: list selection shared by views and dashboard tiles

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: Widget registry and the seven widgets

**Files:**
- Create: `crates/openvibes-console/web/v2/src/dashboards/config.ts` (defensive config readers and parsers)
- Create: `crates/openvibes-console/web/v2/src/dashboards/widgets.tsx` (registry)
- Create: `crates/openvibes-console/web/v2/src/dashboards/tiles.tsx` (views for number, breakdown, attention, list, top-hosts)
- Create: `crates/openvibes-console/web/v2/src/dashboards/tiles2.tsx` (trend, note, and the settings forms), so each file stays under 500 lines
- Modify: `crates/openvibes-console/web/v2/src/views/Overview.tsx`: keep only `greeting()` and `useAttention` (exported); the page itself is replaced in 3b
- Test: `crates/openvibes-console/web/v2/src/dashboards/config.test.ts`

**Interfaces:**
- Consumes: `useListRows`, `LIST_VIEWS` (Task 2); `dailyHosts`, `Trend` (`ui/trend.tsx`); `Stat`, `SeverityBadge`, `ObjectLink` (`ui/bits.tsx`).
- Produces:
  - `config.ts`:
    - `str(config, key, fallback, allowed?)`, `int(config, key, fallback, min, max)`, `list(config, key, allowed)`;
    - `export function noteParts(line: string): ({ text: string } | { href: string })[]`;
    - `export function parseListConfig(config): { view: ListView; params: URLSearchParams; limit: number } | undefined`.
  - `widgets.tsx`:
    - `export type WidgetProps = { widget: Widget }`;
    - `export type SettingsProps = { widget: Widget; onChange: (config: Widget["config"]) => void }`;
    - `export type WidgetDef = { type: WidgetType; label: string; description: string; icon: IconName; size: { w: number; h: number }; defaults: Widget["config"]; View: (props: WidgetProps) => ReactNode; Settings: (props: SettingsProps) => ReactNode }`;
    - `export const widgetDefs: Readonly<Record<WidgetType, WidgetDef>>`;
    - `export function widgetTitle(widget: Widget): string`.
  - `views/Overview.tsx`:
    - `export function greeting(now?: Date): string`;
    - `export function useAttention(include: readonly string[], limit: number): { items: AttentionItem[]; loading: boolean }`.

- [ ] **Step 1: Write the failing config tests**

```ts
import { describe, expect, it } from "vitest";

import { int, list, noteParts, parseListConfig, str } from "./config";

describe("widget configs", () => {
  it("reads configs defensively", () => {
    expect(str({ metric: 5 }, "metric", "agents.active", ["agents.active"])).toBe("agents.active");
    expect(str({ metric: "nope" }, "metric", "agents.active", ["agents.active", "agents.stale"])).toBe("agents.active");
    expect(int({ limit: "8" }, "limit", 5, 1, 20)).toBe(5);
    expect(int({ limit: 99 }, "limit", 5, 1, 20)).toBe(20);
    expect(list({ include: ["stale", "evil"] }, "include", ["exploited", "findings", "stale"])).toEqual(["stale"]);
    expect(list({ include: "stale" }, "include", ["stale"])).toEqual([]);
  });

  it("noteParts links only whole https words and never interprets markup", () => {
    expect(noteParts("See https://wiki.example.test/a now")).toEqual([{ text: "See " }, { href: "https://wiki.example.test/a" }, { text: " now" }]);
    expect(noteParts("javascript:alert(1) <b>bold</b>")).toEqual([{ text: "javascript:alert(1) <b>bold</b>" }]);
    expect(noteParts("http://plain.example.test")).toEqual([{ text: "http://plain.example.test" }]);
  });

  it("parseListConfig accepts only known views and keeps the query", () => {
    expect(parseListConfig({ view: "/findings", query: "severity=critical", limit: 3 })).toMatchObject({ view: "/findings", limit: 3 });
    expect(parseListConfig({ view: "/findings", query: "severity=critical", limit: 3 })?.params.get("severity")).toBe("critical");
    expect(parseListConfig({ view: "/etc/passwd" })).toBeUndefined();
    expect(parseListConfig({ view: "/agents", query: "%%%" })?.params.toString()).toBe("");
  });
});
```

- [ ] **Step 2: Run the tests and watch them fail**

Run: `npx vitest run --config vite.v2.config.ts src/dashboards/config`
Expected: FAIL, "Cannot find module './config'".

- [ ] **Step 3: Implement `config.ts`**

```ts
// Reading widget configs written by any console version: every value is
// checked and falls back to a default, so an old or new config never
// breaks a dashboard.
import { LIST_VIEWS, type ListView } from "../views/rows";
import type { Widget } from "./layout";

type Config = Widget["config"] | Record<string, unknown>;

export function str<T extends string>(config: Config, key: string, fallback: T, allowed?: readonly T[]): T {
  const value = config[key];
  if (typeof value !== "string") return fallback;
  return allowed && !allowed.includes(value as T) ? fallback : (value as T);
}

export function int(config: Config, key: string, fallback: number, min: number, max: number): number {
  const value = config[key];
  return typeof value === "number" && Number.isInteger(value) ? Math.min(max, Math.max(min, value)) : fallback;
}

export function list<T extends string>(config: Config, key: string, allowed: readonly T[]): T[] {
  const value = config[key];
  return Array.isArray(value) ? value.filter((item): item is T => allowed.includes(item as T)) : [];
}

export function noteParts(line: string): ({ text: string } | { href: string })[] {
  const parts: ({ text: string } | { href: string })[] = [];
  let text = "";
  for (const word of line.split(/(\s+)/)) {
    if (/^https:\/\/[^\s<>"']+$/.test(word)) {
      if (text) parts.push({ text });
      text = "";
      parts.push({ href: word });
    } else text += word;
  }
  if (text) parts.push({ text });
  return parts;
}

export function parseListConfig(config: Config): { view: ListView; params: URLSearchParams; limit: number } | undefined {
  const view = config.view;
  if (typeof view !== "string" || !(LIST_VIEWS as readonly string[]).includes(view)) return undefined;
  // URLSearchParams never throws; empty keys (from garbage like "%%%") and
  // panel stacks are dropped, so only real filters reach the list.
  const params = new URLSearchParams(typeof config.query === "string" ? config.query : "");
  params.delete("open");
  for (const key of [...params.keys()]) if (params.get(key) === "") params.delete(key);
  return { view: view as ListView, params, limit: int(config, "limit", 8, 1, 20) };
}
```

- [ ] **Step 4: Run the tests and watch them pass**

Run: `npx vitest run --config vite.v2.config.ts src/dashboards/config`
Expected: PASS (3 tests).

- [ ] **Step 5: Implement the tiles, settings and registry**

`views/Overview.tsx`:
- keep `greeting()`;
- turn the `attention` `useMemo` into
  `export function useAttention(include: readonly string[], limit: number)`.
  It takes the same three loads (exploited vulnerabilities, finding
  groups, stale agents), each skipped when `include` omits it or the
  permission is missing. It returns `{ items: items.slice(0, limit),
  loading }` and also exports `type AttentionItem`;
- have the `Overview` component itself call `useAttention(["exploited",
  "findings", "stale"], 14)`, so the page is unchanged. It stays the `/`
  route until part 3b, Task 3 replaces it and deletes the component.

`dashboards/tiles.tsx` holds one component per type. Each shows a
caption line (`what it counts, your scope`) and handles its permission.

```tsx
import { useResource } from "../api/client";
import type { AgentSummary, FindingSummary, VulnerabilitySummary } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { ObjectLink, SeverityBadge } from "../ui/bits";
import { count } from "../ui/format";
import { Icon } from "../ui/Icon";
import { useAttention } from "../views/Overview";
import { useListRows } from "../views/rows";
import { int, list, parseListConfig, str } from "./config";
import type { WidgetProps } from "./widgets";

export const METRICS = {
  "agents.active": { label: "Hosts online", permission: "agents.read", view: ["/agents", { status: "active" }] },
  "agents.stale": { label: "Stale hosts", permission: "agents.read", view: ["/agents", { status: "stale" }] },
  "agents.revoked": { label: "Revoked hosts", permission: "agents.read", view: ["/agents", { status: "revoked" }] },
  "findings.open.critical": { label: "Open critical findings", permission: "findings.read", view: ["/findings", { severity: "critical" }] },
  "findings.open.high": { label: "Open high findings", permission: "findings.read", view: ["/findings", { severity: "high" }] },
  "findings.open.medium": { label: "Open medium findings", permission: "findings.read", view: ["/findings", { severity: "medium" }] },
  "findings.open.low": { label: "Open low findings", permission: "findings.read", view: ["/findings", { severity: "low" }] },
  "vulns.exploited": { label: "Exploited", permission: "vulnerabilities.read", view: ["/vulnerabilities", { exploited: "true" }] },
  "vulns.reboot_hosts": { label: "Hosts needing a reboot", permission: "vulnerabilities.read", view: ["/vulnerabilities", { reboot: "true" }] },
  "vulns.no_fix": { label: "No fix yet", permission: "vulnerabilities.read", view: ["/vulnerabilities", { nofix: "true" }] },
} as const;
export type Metric = keyof typeof METRICS;
export const METRIC_KEYS = Object.keys(METRICS) as Metric[];

export function Unavailable() {
  return <div className="tile-empty"><Icon name="ban" size={18} /> Not available with your role</div>;
}

export function NumberTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const metric = str(widget.config, "metric", "agents.active", METRIC_KEYS);
  const def = METRICS[metric];
  const allowed = can(def.permission);
  const agents = useResource<AgentSummary>(allowed && metric.startsWith("agents.") ? "/api/v1/agents/summary" : null);
  const findings = useResource<FindingSummary>(allowed && metric.startsWith("findings.") ? "/api/v1/findings/summary" : null);
  const vulns = useResource<VulnerabilitySummary>(allowed && metric.startsWith("vulns.") ? "/api/v1/vulnerabilities/summary" : null);
  if (!allowed) return <Unavailable />;
  const value = metric === "agents.active" ? agents.data?.active : metric === "agents.stale" ? agents.data?.stale : metric === "agents.revoked" ? agents.data?.revoked
    : metric.startsWith("findings.open.") ? findings.data?.[metric.slice(14) as "critical" | "high" | "medium" | "low"]
      : metric === "vulns.exploited" ? vulns.data?.exploited : metric === "vulns.reboot_hosts" ? vulns.data?.reboot_hosts : vulns.data?.no_fix;
  const tone = value && (metric === "findings.open.critical" || metric === "vulns.exploited") ? "crit" : value && metric === "agents.stale" ? "warn" : undefined;
  return (
    <button type="button" className="tile-number" onClick={() => nav.view(def.view[0], def.view[1])}>
      <span className={`stat__value num${tone ? ` stat__value--${tone}` : ""}`}>{value === undefined ? "…" : count(value)}</span>
    </button>
  );
}

export function BreakdownTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const source = str(widget.config, "source", "findings", ["findings", "vulnerabilities", "agents"] as const);
  const permission = source === "findings" ? "findings.read" : source === "agents" ? "agents.read" : "vulnerabilities.read";
  const allowed = can(permission);
  const findings = useResource<FindingSummary>(allowed && source === "findings" ? "/api/v1/findings/summary" : null);
  const vulns = useResource<VulnerabilitySummary>(allowed && source === "vulnerabilities" ? "/api/v1/vulnerabilities/summary" : null);
  const agents = useResource<AgentSummary>(allowed && source === "agents" ? "/api/v1/agents/summary" : null);
  if (!allowed) return <Unavailable />;
  const parts: { key: string; label: string; value: number; tone: string; go: () => void }[] =
    source === "findings" ? (["critical", "high", "medium", "low"] as const).map((s) => ({ key: s, label: s, value: findings.data?.[s] ?? 0, tone: s, go: () => nav.view("/findings", { severity: s }) }))
      : source === "vulnerabilities" ? (vulns.data?.by_severity ?? []).map((row) => ({ key: row.severity, label: row.severity, value: row.count, tone: row.severity, go: () => nav.view("/vulnerabilities", { severity: row.severity }) }))
        : (["active", "stale", "revoked", "imported"] as const).map((s) => ({ key: s, label: s, value: agents.data?.[s] ?? 0, tone: { active: "low", stale: "medium", revoked: "high", imported: "unrated" }[s], go: () => nav.view("/agents", { status: s }) }));
  return (
    <div className="stack">
      <div className="bar" role="img" aria-label={parts.map((p) => `${p.value} ${p.label}`).join(", ")}>
        {parts.map((p) => p.value > 0 && <span key={p.key} className={p.tone} style={{ flexGrow: p.value }} />)}
      </div>
      <div className="legend">
        {parts.map((p) => <button key={p.key} type="button" className="legend__item" onClick={p.go}><span className={`legend__dot ${p.tone}`} />{p.label}<span className="num">{count(p.value)}</span></button>)}
      </div>
    </div>
  );
}

export function AttentionTile({ widget }: WidgetProps) {
  const include = list(widget.config, "include", ["exploited", "findings", "stale"] as const);
  const { items, loading } = useAttention(include.length ? include : ["exploited", "findings", "stale"], int(widget.config, "limit", 8, 1, 20));
  if (loading && items.length === 0) return <div className="skeleton" />;
  if (items.length === 0) return <div className="tile-empty"><Icon name="check" size={18} /> All clear</div>;
  return (
    <ul className="attention__list">
      {items.map((item) => (
        <li key={item.key}>
          <ObjectLink to={item.to} fromList className="attention__row">
            <span className={`attention__icon attention__icon--${item.severity}`}><Icon name={item.icon} size={16} /></span>
            <span className="grow"><span className="attention__title truncate">{item.title}</span><span className="attention__meta">{item.meta}</span></span>
            {item.severity === "stale" ? <span className="badge badge--warn">Stale</span> : <SeverityBadge severity={item.severity} />}
          </ObjectLink>
        </li>
      ))}
    </ul>
  );
}

export function ListTile({ widget }: WidgetProps) {
  const parsed = parseListConfig(widget.config);
  if (!parsed) return <div className="tile-empty"><Icon name="alert" size={18} /> This list is not available</div>;
  return <ListTileBody view={parsed.view} params={parsed.params} limit={parsed.limit} />;
}

function ListTileBody({ view, params, limit }: NonNullable<ReturnType<typeof parseListConfig>>) {
  const { can } = useSession();
  const permission = { "/findings": "findings.read", "/vulnerabilities": "vulnerabilities.read", "/agents": "agents.read", "/audit": "audit.read" }[view] as "findings.read";
  const { rows, total, loading, error } = useListRows(view, params);
  if (!can(permission, view === "/audit")) return <Unavailable />;
  if (error) return <div className="tile-empty"><Icon name="alert" size={18} /> {error.message}</div>;
  if (loading) return <div className="skeleton" />;
  return (
    <div className="tile-list">
      {rows.length === 0 ? <div className="tile-empty"><Icon name="check" size={18} /> Nothing matches</div> : (
        <ul className="list list--plain">
          {rows.slice(0, limit).map((row) => (
            <li key={row.key}><ObjectLink to={row.open} className="list__row">
              <span className={`badge badge--${row.badge.tone}`}>{row.badge.label}</span>
              <span className="grow truncate">{row.title}</span><span className="subtle nowrap">{row.meta}</span>
            </ObjectLink></li>
          ))}
        </ul>
      )}
      <button type="button" className="link-button tile-more" onClick={() => nav.view(view, Object.fromEntries(params))}>Open list ({count(total)})</button>
    </div>
  );
}

export function TopHostsTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const summary = useResource<VulnerabilitySummary>(can("vulnerabilities.read") ? "/api/v1/vulnerabilities/summary" : null);
  if (!can("vulnerabilities.read")) return <Unavailable />;
  return (
    <ul className="list list--plain">
      {(summary.data?.top_hosts ?? []).slice(0, int(widget.config, "limit", 6, 1, 10)).map((host) => (
        <li key={host.agent_id}><ObjectLink to={{ kind: "agent", id: host.agent_id }} className="list__row">
          <Icon name="agents" size={15} className="subtle" /><span className="grow truncate">{host.hostname ?? host.agent_id}</span>
          {host.serious > 0 && <span className="badge badge--high badge--plain num">{host.serious} serious</span>}<span className="subtle num">{host.open}</span>
        </ObjectLink></li>
      ))}
    </ul>
  );
}
```

`dashboards/tiles2.tsx`:

```tsx
import { useMemo } from "react";

import { useAllPages } from "../api/client";
import { useSession } from "../app/session";
import { daysAgo } from "../ui/format";
import { Trend, dailyHosts } from "../ui/trend";
import { LIST_VIEWS } from "../views/rows";
import { int, list, noteParts, str } from "./config";
import { METRICS, METRIC_KEYS, Unavailable } from "./tiles";
import type { SettingsProps, WidgetProps } from "./widgets";

export function TrendTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const finding = str(widget.config, "finding", "", undefined);
  const days = [7, 14, 30].includes(int(widget.config, "days", 14, 7, 30)) ? int(widget.config, "days", 14, 7, 30) : 14;
  const [set = "", rule = ""] = finding.split("/");
  const history = useAllPages<{ agent_id: string; observed_day: string }>(can("findings.read") && set && rule
    ? `/api/v1/findings/history?since=${encodeURIComponent(daysAgo(days - 1))}&rule_set_id=${encodeURIComponent(set)}&rule_id=${encodeURIComponent(rule)}` : null, 3000);
  const counts = useMemo(() => dailyHosts(history.data ?? [], days), [history.data, days]);
  if (!can("findings.read")) return <Unavailable />;
  if (!set || !rule) return <div className="tile-empty">Choose a finding in this tile's settings</div>;
  return <Trend counts={counts} label={`hosts reporting ${rule}`} />;
}

export function NoteTile({ widget }: WidgetProps) {
  const lines = Array.isArray(widget.config.text) ? (widget.config.text as unknown[]).filter((line): line is string => typeof line === "string").slice(0, 16) : [];
  return (
    <div className="tile-note">
      {lines.map((line, index) => (
        <p key={index}>{noteParts(line).map((part, i) => "href" in part
          ? <a key={i} href={part.href} target="_blank" rel="noreferrer noopener">{part.href}</a>
          : <span key={i}>{part.text}</span>)}</p>
      ))}
    </div>
  );
}

const field = (label: string, control: React.ReactNode) => <label className="field">{label}{control}</label>;

export function NumberSettings({ widget, onChange }: SettingsProps) {
  const metric = str(widget.config, "metric", "agents.active", METRIC_KEYS);
  return field("Count", <select className="select" value={metric} onChange={(e) => onChange({ ...widget.config, metric: e.target.value })}>
    {METRIC_KEYS.map((key) => <option key={key} value={key}>{METRICS[key].label}</option>)}
  </select>);
}

export function BreakdownSettings({ widget, onChange }: SettingsProps) {
  return field("Break down", <select className="select" value={str(widget.config, "source", "findings", ["findings", "vulnerabilities", "agents"] as const)}
    onChange={(e) => onChange({ ...widget.config, source: e.target.value })}>
    <option value="findings">Open findings by severity</option><option value="vulnerabilities">Vulnerabilities by severity</option><option value="agents">Hosts by status</option>
  </select>);
}

export function AttentionSettings({ widget, onChange }: SettingsProps) {
  const include = list(widget.config, "include", ["exploited", "findings", "stale"] as const);
  const toggle = (value: string) => onChange({ ...widget.config, include: include.includes(value as never) ? include.filter((v) => v !== value) : [...include, value] });
  return (
    <div className="stack">
      {(["exploited", "findings", "stale"] as const).map((value) => (
        <label key={value} className="row"><input type="checkbox" checked={include.length === 0 || include.includes(value)} onChange={() => toggle(value)} />
          {{ exploited: "Exploited vulnerabilities", findings: "Open critical and high findings", stale: "Hosts that stopped reporting" }[value]}</label>
      ))}
      {field("Show at most", <input className="input" type="number" min={1} max={20} value={int(widget.config, "limit", 8, 1, 20)} onChange={(e) => onChange({ ...widget.config, limit: Number(e.target.value) })} />)}
    </div>
  );
}

export function ListSettings({ widget, onChange }: SettingsProps) {
  return (
    <div className="stack">
      {field("List", <select className="select" value={str(widget.config, "view", "/findings", LIST_VIEWS)} onChange={(e) => onChange({ ...widget.config, view: e.target.value })}>
        {LIST_VIEWS.map((v) => <option key={v} value={v}>{v.slice(1)}</option>)}
      </select>)}
      {field("Filters (as in the list's address, e.g. severity=critical)", <input className="input mono" value={str(widget.config, "query", "")} onChange={(e) => onChange({ ...widget.config, query: e.target.value })} />)}
      {field("Rows", <input className="input" type="number" min={1} max={20} value={int(widget.config, "limit", 8, 1, 20)} onChange={(e) => onChange({ ...widget.config, limit: Number(e.target.value) })} />)}
    </div>
  );
}

export function TrendSettings({ widget, onChange }: SettingsProps) {
  return (
    <div className="stack">
      {field("Finding (rule set/rule, e.g. hardening-ssh/SSH-002)", <input className="input mono" value={str(widget.config, "finding", "")} onChange={(e) => onChange({ ...widget.config, finding: e.target.value })} />)}
      {field("Days", <select className="select" value={int(widget.config, "days", 14, 7, 30)} onChange={(e) => onChange({ ...widget.config, days: Number(e.target.value) })}>
        <option value={7}>7</option><option value={14}>14</option><option value={30}>30</option></select>)}
    </div>
  );
}

export function TopHostsSettings({ widget, onChange }: SettingsProps) {
  return field("Hosts", <input className="input" type="number" min={1} max={10} value={int(widget.config, "limit", 6, 1, 10)} onChange={(e) => onChange({ ...widget.config, limit: Number(e.target.value) })} />);
}

export function NoteSettings({ widget, onChange }: SettingsProps) {
  const text = Array.isArray(widget.config.text) ? (widget.config.text as string[]).join("\n") : "";
  return field("Text (plain; https:// links become clickable)", <textarea className="textarea" rows={6} maxLength={16 * 257} value={text}
    onChange={(e) => onChange({ ...widget.config, text: e.target.value.split("\n").slice(0, 16).map((line) => line.slice(0, 256)) })} />);
}
```

`dashboards/widgets.tsx`:

```tsx
// The widget types a dashboard can hold. Adding one: an entry here, its
// type in layout.ts's WIDGET_TYPES, and the same name in the server's
// allow-list (openvibes-console/src/dashboards.rs).
import type { ReactNode } from "react";

import type { IconName } from "../ui/Icon";
import type { Widget, WidgetType } from "./layout";
import { AttentionTile, BreakdownTile, ListTile, NumberTile, TopHostsTile } from "./tiles";
import { AttentionSettings, BreakdownSettings, ListSettings, NoteSettings, NoteTile, NumberSettings, TopHostsSettings, TrendSettings, TrendTile } from "./tiles2";

export type WidgetProps = { widget: Widget };
export type SettingsProps = { widget: Widget; onChange: (config: Widget["config"]) => void };
export type WidgetDef = {
  type: WidgetType; label: string; description: string; icon: IconName; size: { w: number; h: number };
  defaults: Widget["config"]; View: (props: WidgetProps) => ReactNode; Settings: (props: SettingsProps) => ReactNode;
};

export const widgetDefs: Readonly<Record<WidgetType, WidgetDef>> = {
  number: { type: "number", label: "Number", description: "One count that opens its list", icon: "activity", size: { w: 3, h: 2 }, defaults: { metric: "findings.open.critical" }, View: NumberTile, Settings: NumberSettings },
  breakdown: { type: "breakdown", label: "Breakdown", description: "A severity or status bar", icon: "filter", size: { w: 4, h: 3 }, defaults: { source: "findings" }, View: BreakdownTile, Settings: BreakdownSettings },
  attention: { type: "attention", label: "Needs attention", description: "Exploited, serious and silent, in one list", icon: "alert", size: { w: 7, h: 7 }, defaults: { include: ["exploited", "findings", "stale"], limit: 8 }, View: AttentionTile, Settings: AttentionSettings },
  list: { type: "list", label: "List", description: "The first rows of any list, with its filters", icon: "findings", size: { w: 6, h: 6 }, defaults: { view: "/findings", query: "severity=critical", limit: 8 }, View: ListTile, Settings: ListSettings },
  trend: { type: "trend", label: "Trend", description: "Hosts reporting a finding per day", icon: "activity", size: { w: 4, h: 3 }, defaults: { finding: "", days: 14 }, View: TrendTile, Settings: TrendSettings },
  "top-hosts": { type: "top-hosts", label: "Most exposed hosts", description: "Hosts with the most serious vulnerabilities", icon: "agents", size: { w: 5, h: 6 }, defaults: { limit: 6 }, View: TopHostsTile, Settings: TopHostsSettings },
  note: { type: "note", label: "Note", description: "Plain text for your team", icon: "help", size: { w: 4, h: 3 }, defaults: { text: [] }, View: NoteTile, Settings: NoteSettings },
};

export function widgetTitle(widget: Widget): string {
  const custom = widget.config.title;
  return typeof custom === "string" && custom.trim() ? custom.trim() : widgetDefs[widget.type].label;
}
```

Add to `styles/panels.css`:

```css
.tile-empty { display: flex; align-items: center; gap: 8px; color: var(--text-3); font-size: 13px; padding: 8px 0; }
.tile-number { all: unset; cursor: pointer; display: block; }
.tile-number:focus-visible { outline: 2px solid var(--focus); border-radius: var(--r-1); }
.tile-list { display: grid; gap: 6px; }
.tile-more { justify-self: start; font-size: 13px; }
.tile-note p { margin: 0 0 6px; overflow-wrap: anywhere; white-space: pre-wrap; }
```

- [ ] **Step 6: Typecheck, lint, test and commit**

Run: `npx tsc --noEmit && npx eslint . --max-warnings 0 && npx vitest run --config vite.v2.config.ts 2>&1 | grep -E "Tests |×"`
Expected: no type or lint errors; all tests pass.

```bash
git add crates/openvibes-console/web/v2/src
git commit -m "Console v2: dashboard widgets (number, breakdown, attention, list, trend, top hosts, note)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
