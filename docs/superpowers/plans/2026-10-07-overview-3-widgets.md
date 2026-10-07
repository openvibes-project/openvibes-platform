# Overview clarity 3: Overview, trends and Graph widget — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The built-in Overview counts all three kinds clearly with 30-day trends, and users can add trends and graphs for any catalogue count.

**Architecture:** A pure geometry module (`ui/linechart.ts`: monotone and stepped paths, whole-number ticks) and one `LineChart` component (sparkline and full variants) draw every trend. The web count catalogue mirrors the server's (plan 2). Number tiles gain trend settings; a new `graph` widget type is allow-listed on the server. Needs attention, Breakdown and Most exposed hosts learn the three kinds; a small server endpoint ranks hosts across kinds. The demo API serves all new endpoints so the Pages preview keeps working.

**Tech Stack:** React + TypeScript (vitest, Playwright), Rust (axum) for two small server pieces.

**Spec:** `docs/superpowers/specs/2026-10-07-overview-clarity-design.md` §4, §6. **Depends on:** plans 1 and 2 merged (compliance names; `/api/v1/metrics/history`, `platform_store::history`).

## Global Constraints

- Look: today's tiles and tokens (`web/src/styles/tokens.css`). Lines use `--accent`; multi-line graphs use a fixed categorical order validated with the dataviz script (`node <dataviz>/scripts/validate_palette.js "<hexes>" --mode dark` and `--mode light`); severity colours are never line colours.
- Line style default **smooth** (monotone cubic, Fritsch-Carlson); option **stepped** (step-after). Line width 2px; dot on today's value; recessive grid; whole-number ticks only.
- Number trend: off / 7 / 30 / 90 (default off; built-in Overview 30). Graph: 1–4 counts, 7 / 30 / 90 / 365, optional title.
- Vulnerability list links use the page's own values: high → `severity=important`, medium → `severity=moderate`.
- Missing days are gaps; fewer than 2 points → "Collecting since <first day>".
- Every chart has a text alternative (`aria-label` summary) and a "Show as table" toggle.

## Review Focus

1. Built-in Overview on a fresh install (one live point): tiles show numbers and "Collecting since …", no flat fake line (Task 3 unit + Task 8 e2e).
2. A role without `alarms.read`: Critical/High tiles say "Not available with your role" instead of a partial sum (Task 4 test).
3. Hover at the left and right edge of a 365-day graph shows the first and last day, and the tooltip stays inside the tile (Task 2 e2e).
4. A gap of missing days (maintenance didn't run) breaks the line rather than drawing a slope across it (Task 1 test).
5. Counts of 0 everywhere: the curve sits on the baseline and ticks show 0/1/2, not 0/0.5/1 (Task 1 test).

---

### Task 1: Chart geometry (pure)

**Files:** Create `web/src/ui/linechart.ts`, `web/src/ui/linechart.test.ts`

**Interfaces — Produces:**
- `type Pt = { x: number; y: number }`
- `monotonePath(points: Pt[]): string` — SVG path, Fritsch-Carlson
- `steppedPath(points: Pt[]): string` — step-after
- `segments<T extends { day: string }>(points: T[]): T[][]` — split where consecutive days are not adjacent
- `niceMax(max: number): number` — smallest of 2,4,6,8,10,20,30,40,50,60,80,100,… ≥ max (always even, ≥ 2)
- `ticks(max: number): number[]` — `[0, max/2, max]`

- [ ] **Step 1: Failing tests**

```ts
import { describe, expect, it } from "vitest";
import { monotonePath, niceMax, segments, steppedPath, ticks } from "./linechart";

const ys = (d: string) => [...d.matchAll(/[ -]?\d+(?:\.\d+)?,(-?\d+(?:\.\d+)?)/g)].map((m) => Number(m[1]));

describe("linechart", () => {
  it("monotone curve never leaves the range of its neighbours", () => {
    const pts = [0, 5, 0, 0, 3, 3, 1].map((v, i) => ({ x: i * 10, y: 100 - v * 10 }));
    for (const y of ys(monotonePath(pts))) { expect(y).toBeGreaterThanOrEqual(50); expect(y).toBeLessThanOrEqual(100); }
  });
  it("flat input gives a flat curve", () => {
    expect(new Set(ys(monotonePath([0, 1, 2].map((i) => ({ x: i, y: 7 })))))).toEqual(new Set([7]));
  });
  it("stepped path moves horizontally then vertically", () => {
    expect(steppedPath([{ x: 0, y: 5 }, { x: 10, y: 2 }])).toBe("M0,5H10V2");
  });
  it("splits at missing days", () => {
    const s = segments([{ day: "2026-10-01" }, { day: "2026-10-02" }, { day: "2026-10-05" }]);
    expect(s.map((g) => g.length)).toEqual([2, 1]);
  });
  it("uses whole-number ticks", () => {
    expect(niceMax(0)).toBe(2); expect(niceMax(5)).toBe(6); expect(niceMax(11)).toBe(20);
    expect(ticks(niceMax(1))).toEqual([0, 1, 2]);
  });
});
```

- [ ] **Step 2:** `npm --prefix crates/openvibes-console/web test -- linechart` — FAIL.
- [ ] **Step 3: Implement**

```ts
// Geometry for the console's line charts: monotone (no overshoot) or
// stepped paths, gaps at missing days, whole-number ticks.
export type Pt = { x: number; y: number };

export function steppedPath(p: Pt[]): string {
  if (p.length === 0) return "";
  return p.slice(1).reduce((d, q) => `${d}H${q.x}V${q.y}`, `M${p[0]!.x},${p[0]!.y}`);
}

export function monotonePath(p: Pt[]): string {
  const n = p.length;
  if (n === 0) return "";
  if (n === 1) return `M${p[0]!.x},${p[0]!.y}`;
  const d = p.slice(0, -1).map((a, i) => (p[i + 1]!.y - a.y) / (p[i + 1]!.x - a.x));
  const m = p.map((_, i) => (i === 0 ? d[0]! : i === n - 1 ? d[n - 2]! : d[i - 1]! * d[i]! <= 0 ? 0 : (d[i - 1]! + d[i]!) / 2));
  for (let i = 0; i < n - 1; i++) {
    if (d[i] === 0) { m[i] = 0; m[i + 1] = 0; continue; }
    const a = m[i]! / d[i]!, b = m[i + 1]! / d[i]!, h = a * a + b * b;
    if (h > 9) { const t = 3 / Math.sqrt(h); m[i] = t * a * d[i]!; m[i + 1] = t * b * d[i]!; }
  }
  let path = `M${p[0]!.x},${p[0]!.y}`;
  for (let i = 0; i < n - 1; i++) {
    const a = p[i]!, b = p[i + 1]!, h = (b.x - a.x) / 3;
    path += `C${a.x + h},${a.y + m[i]! * h} ${b.x - h},${b.y - m[i + 1]! * h} ${b.x},${b.y}`;
  }
  return path;
}

const DAY = 86_400_000;
export function segments<T extends { day: string }>(points: T[]): T[][] {
  const out: T[][] = [];
  for (const pt of points) {
    const last = out.at(-1)?.at(-1);
    if (last && Date.parse(pt.day) - Date.parse(last.day) === DAY) out.at(-1)!.push(pt); else out.push([pt]);
  }
  return out;
}

const STEPS = [2, 4, 6, 8, 10, 20, 30, 40, 50, 60, 80, 100];
export function niceMax(max: number): number {
  const step = STEPS.find((s) => s >= max);
  if (step) return step;
  const mag = 10 ** Math.floor(Math.log10(max));
  return [2, 4, 6, 8, 10].map((k) => k * mag).find((s) => s >= max) ?? 20 * mag;
}
export const ticks = (max: number) => [0, max / 2, max];
```

- [ ] **Step 4:** run tests — PASS. **Step 5:** commit `"Web: line chart geometry"`.

### Task 2: `LineChart` component and history hook

**Files:** Create `web/src/ui/LineChart.tsx`, `web/src/dashboards/history.ts`; Modify `web/src/styles/components.css` (`.linechart*` rules using tokens).

**Interfaces — Produces:**
- `type Series = { label: string; points: { day: string; value: number }[] }`
- `<LineChart series={Series[]} variant="spark" | "full" smooth={boolean} />`
- `useHistory(metric: string | null, days: number): { data?: { day: string; value: number }[]; error?: Error; loading: boolean }` — wraps `useResource` on `/api/v1/metrics/history?metric=…&days=…`

Component rules (from the approved mockup `graphs-v3.html`): measures its width with `ResizeObserver` and draws at pixel size (no stretched viewBox); `spark` = 36px high, baseline only, dot on last point; `full` = 150px, grid at `ticks`, y labels, x labels at first / middle / "Today", legend + end labels when `series.length > 1`; hover: crosshair, dots, tooltip with day and every series value, clamped inside the tile; area fill `--accent-soft` for a single series only; `segments` for gaps; "Show as table" button renders a `<table>` of day × series; `role="img"` + `aria-label` "<label>: <first day> to <last day>, now <value>".

- [ ] **Step 1:** Write the component and hook. **Step 2:** Add `web/e2e/demo/charts.spec.ts`:

```ts
import { expect, test } from "@playwright/test";

test("graph hover shows the edge days and stays inside its tile", async ({ page }) => {
  await page.goto("/dashboards/new");  // demo: create a dashboard with one Graph widget, 365 days (use the editor's add-widget flow as dashboards.spec.ts does)
  const chart = page.getByRole("img", { name: /Active alarms/ });
  const box = (await chart.boundingBox())!;
  await page.mouse.move(box.x + 1, box.y + box.height / 2);
  await expect(page.locator(".linechart__tip")).toContainText(/\d/);
  await page.mouse.move(box.x + box.width - 1, box.y + box.height / 2);
  await expect(page.locator(".linechart__tip")).toContainText("Today");
  const tip = (await page.locator(".linechart__tip").boundingBox())!;
  const tile = (await chart.locator("xpath=ancestor::*[contains(@class,'tile')][1]").boundingBox())!;
  expect(tip.x + tip.width).toBeLessThanOrEqual(tile.x + tile.width);
});
```

- [ ] **Step 3:** demo API: in `web/src/demo/server.ts` serve `/api/v1/metrics/history` from a deterministic generator (seeded by metric id, 365 days, ending at today's value from the demo summaries) and respect `days`. Add a case to `demo/server.test.ts`: `days=30` returns ≤ 30 points ending today.
- [ ] **Step 4:** `npm test` and `npm run test:e2e:demo -- charts` — PASS. Render once in Firefox, dark and light, and eyeball for label collisions. **Step 5:** commit `"Web: LineChart and history hook"`.

### Task 3: Count catalogue (web)

**Files:** Modify `web/src/dashboards/tiles.tsx` (`METRICS`), Create `web/src/dashboards/catalogue.test.ts`

Replace `METRICS` with entries matching plan 2's server catalogue IDs exactly. Each entry: `{ label, permissions: string[], view: [path, params], parts?: [kind, metricId][] }`. Labels: `all.open.critical` "Critical", `all.open.high` "High", `alarms.active` "Active alarms", `alarms.active.<sev>` "Active <sev> alarms", `vulns.open.<sev>` "Open <sev> vulnerabilities", `vulns.exploited` "Exploited vulnerabilities", `vulns.no_fix` "No fix yet", `vulns.reboot_hosts` "Hosts needing a reboot", `compliance.open.<sev>` "Open <sev> compliance findings", `agents.*` "Hosts online / Stale hosts / Revoked hosts". Views: alarms `["/alarms", { severity }]`, vulns `["/vulnerabilities", { severity: critical|important|moderate|low }]`, compliance `["/compliance", { severity }]`. Cross-kind entries carry `parts` = the three per-kind IDs.

- [ ] **Step 1: Failing test**

```ts
import { describe, expect, it } from "vitest";
import { METRICS } from "./tiles";

describe("catalogue", () => {
  it("cross-kind counts need all three read permissions and link each part", () => {
    expect(METRICS["all.open.high"].permissions).toEqual(["alarms.read", "vulnerabilities.read", "compliance.read"]);
    expect(METRICS["all.open.high"].parts).toEqual([["alarm", "alarms.active.high"], ["vulnerability", "vulns.open.high"], ["compliance", "compliance.open.high"]]);
    expect(METRICS["vulns.open.high"].view).toEqual(["/vulnerabilities", { severity: "important" }]);
  });
  it("matches the server catalogue IDs", () => {
    expect(Object.keys(METRICS).sort()).toMatchSnapshot();
  });
});
```

- [ ] **Step 2:** FAIL → **Step 3:** implement; a tile's value is the last point of `useHistory(id, 7)` (the history API's live "today" point, plan 2), so every count has one source and the number always equals the end of its trend; per-kind fine-print values come the same way from each part's ID. **Step 4:** PASS; review the snapshot against plan 2's table by eye. **Step 5:** commit `"Web: count catalogue"`.

### Task 4: Number tile trend, delta and fine print

**Files:** Modify `web/src/dashboards/tiles.tsx` (`NumberTile`), `tiles2.tsx` (`NumberSettings`), `defaults.ts`; Test `web/src/dashboards/number.test.ts` (pure helpers) + e2e.

- [ ] **Step 1: Failing test** for helpers exported from `tiles.tsx`:

```ts
import { describe, expect, it } from "vitest";
import { delta, permitted } from "./tiles";

describe("number tile", () => {
  it("describes the change over the period", () => {
    expect(delta([{ day: "2026-10-01", value: 3 }, { day: "2026-10-07", value: 1 }])).toBe("−2");
    expect(delta([{ day: "2026-10-01", value: 1 }, { day: "2026-10-07", value: 1 }])).toBe("no change");
    expect(delta([{ day: "2026-10-07", value: 1 }])).toBeNull();
  });
  it("needs every permission of a cross-kind count", () => {
    const can = (p: string) => p !== "alarms.read";
    expect(permitted("all.open.critical", can)).toBe(false);
    expect(permitted("vulns.exploited", can)).toBe(true);
  });
});
```

- [ ] **Step 2:** FAIL → **Step 3:** implement: settings `trend` (0|7|30|90, select labelled "Trend") and `line` ("smooth"|"stepped", shown only when trend > 0); tile shows number, `delta` beside it, `<LineChart variant="spark">` when trend > 0 and ≥ 2 points, else "Collecting since <day>" when trend > 0; fine print for entries with `parts`: "0 alarms · 1 vulnerability · 0 compliance" (correct plurals), each part a link to its view. **Step 4:** PASS. **Step 5:** commit `"Web: Number tile trend and per-kind fine print"`.

### Task 5: Graph widget (web + server allow-list)

**Files:** Modify `crates/openvibes-console/src/dashboards.rs` (`WIDGET_TYPES: [&str; 8]` adding `"graph"`), its test module (a layout with a `graph` widget validates; config `metrics` array of ≤ 4 strings already passes `valid_config_value`); `web/src/dashboards/layout.ts` (`WIDGET_TYPES`), `widgets.tsx` (entry `graph: { label: "Graph", description: "Counts over time", icon: "activity", … }`), `defaults.ts` (size `{ w: 6, h: 4 }`, config `{ metrics: ["alarms.active"], days: 30, line: "smooth" }`), `tiles2.tsx` (`GraphTile`, `GraphSettings`).

- [ ] **Step 1: Failing Rust test** in `dashboards.rs` tests: `validate_layout(&json!({"schema":1,"widgets":[{"id":"g","type":"graph","x":0,"y":0,"w":6,"h":4,"config":{"metrics":["alarms.active","vulns.exploited"],"days":30}}]}))` is `Ok`. **Step 2:** FAIL. **Step 3:** implement both sides; `GraphSettings`: up to four selects of catalogue counts ("+ Add count" until 4, remove buttons), period select (7/30/90/365), line style, title; `GraphTile`: one `useHistory` per metric, `<LineChart variant="full">`, "Not available with your role" if any metric isn't permitted. Pick the categorical order and validate it (Global Constraints). **Step 4:** `cargo test -p openvibes-console dashboards` and web tests — PASS. **Step 5:** commit `"Dashboards: Graph widget"`.

### Task 6: Needs attention, Breakdown, Most exposed hosts

**Files:** `web/src/dashboards/attention.tsx`, `tiles.tsx` (`BreakdownTile`, `TopHostsTile`), `tiles2.tsx` settings; server: `crates/platform-store/src/history.rs` (`top_hosts`), `crates/openvibes-console/src/metrics.rs` (`GET /api/v1/metrics/top-hosts?limit=1..10`), OpenAPI + client regen; demo server route.

- **Needs attention:** new kind `serious` = `/api/v1/vulnerabilities?severity=critical` and `?severity=important` (limit 20 each); each row's meta starts with its kind label ("Alarm", "Vulnerability", "Compliance", "Host"); ranking: critical alarm −1, exploited 0, critical (any kind) 1, high (any kind) 3, stale 5. Default kinds for the Overview: alarms, exploited, serious, compliance, stale.
- **Breakdown:** sources `alarms` (active by severity), `vulnerabilities`, `compliance`, `agents`; titles "Active alarms by severity", "Vulnerabilities by severity", "Compliance findings by severity", "Hosts by status".
- **Most exposed hosts:** setting `kinds`: `all` (default) | `vulnerabilities`. `all` calls `/api/v1/metrics/top-hosts` (store: `HOST_COUNTS_SQL` ordered by critical+high of all kinds, then total; needs the three read permissions with one scope, else 403 and the tile says "Not available with your role — choose Vulnerabilities only"); fine print "all kinds".

- [ ] **Step 1: Failing tests:** store test `top_hosts` orders a host with 2 critical compliance findings above one with 1 high vulnerability; console test for permissions/scope like plan 2 Task 4; web unit test for the attention ranking with one item of each kind. **Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS. **Step 5:** commit `"Dashboards: three kinds in attention, breakdown and top hosts"`.

### Task 7: Built-in Overview

**Files:** `web/src/dashboards/builtin.ts`, `web/e2e/demo/dashboards.spec.ts`

```ts
export const BUILTIN_LAYOUT: Layout = {
  schema: 1,
  widgets: [
    { id: "alarms", type: "number", x: 0, y: 0, w: 3, h: 3, config: { metric: "alarms.active", trend: 30, line: "smooth" } },
    { id: "critical", type: "number", x: 3, y: 0, w: 3, h: 3, config: { metric: "all.open.critical", trend: 30, line: "smooth" } },
    { id: "high", type: "number", x: 6, y: 0, w: 3, h: 3, config: { metric: "all.open.high", trend: 30, line: "smooth" } },
    { id: "exploited", type: "number", x: 9, y: 0, w: 3, h: 3, config: { metric: "vulns.exploited", trend: 30, line: "smooth" } },
    { id: "attention", type: "attention", x: 0, y: 3, w: 7, h: 9, config: { include: ["alarms", "exploited", "serious", "compliance", "stale"], limit: 14 } },
    { id: "vulns", type: "breakdown", x: 7, y: 3, w: 5, h: 2, config: { source: "vulnerabilities" } },
    { id: "compliance", type: "breakdown", x: 7, y: 5, w: 5, h: 2, config: { source: "compliance" } },
    { id: "hosts", type: "top-hosts", x: 7, y: 7, w: 5, h: 5, config: { limit: 7, kinds: "all" } },
    { id: "online", type: "number", x: 0, y: 12, w: 4, h: 2, config: { metric: "agents.active", title: "Fleet · online" } },
    { id: "stale", type: "number", x: 4, y: 12, w: 4, h: 2, config: { metric: "agents.stale", title: "Fleet · stale" } },
    { id: "reboot", type: "number", x: 8, y: 12, w: 4, h: 2, config: { metric: "vulns.reboot_hosts", title: "Fleet · need a reboot" } },
  ],
};
```

- [ ] **Step 1: Failing e2e** in `dashboards.spec.ts`: on the demo Overview, the tile "Critical" shows a number equal to the sum of its three fine-print parts, clicking "vulnerability" in its fine print opens `/vulnerabilities?severity=critical`, the "Needs attention" list contains a row starting "Vulnerability", and no visible text matches `/\bfindings?\b/i` except "compliance finding(s)". **Step 2:** FAIL. **Step 3:** update `builtin.ts`. **Step 4:** PASS (demo and `bash scripts/test-console-e2e.sh` live). **Step 5:** commit `"Overview: three kinds and 30-day trends"`.

### Task 8: Docs and gate

- [ ] `docs/components/console-web.md` (dashboards section: widget list, Number trend, Graph widget, Overview layout), `docs/components/openvibes-console.md` (`/api/v1/metrics/top-hosts`).
- [ ] Gate: `testing.md` §2 + browser checks (`test-console-e2e.sh`, `test:e2e:demo`, all three Playwright browsers). Screenshot the Overview in dark and light for the PR body. Open PR 3.
