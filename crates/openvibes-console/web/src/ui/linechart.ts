// Geometry for the console's line charts: monotone (no overshoot) or
// stepped paths, gaps at missing days, whole-number ticks.
export type Pt = { x: number; y: number };

// Indexed read that fails loudly on an out-of-range index (an internal invariant).
function get<T>(arr: readonly T[], i: number): T {
  const v = arr[i];
  if (v === undefined) throw new RangeError(`index ${i} out of range`);
  return v;
}

export function steppedPath(p: Pt[]): string {
  if (p.length === 0) return "";
  const first = get(p, 0);
  return p.slice(1).reduce((d, q) => `${d}H${q.x}V${q.y}`, `M${first.x},${first.y}`);
}

export function monotonePath(p: Pt[]): string {
  const n = p.length;
  if (n === 0) return "";
  const first = get(p, 0);
  if (n === 1) return `M${first.x},${first.y}`;
  const d = p.slice(0, -1).map((a, i) => (get(p, i + 1).y - a.y) / (get(p, i + 1).x - a.x));
  const m = p.map((_, i) => {
    if (i === 0) return get(d, 0);
    if (i === n - 1) return get(d, n - 2);
    const prev = get(d, i - 1);
    const next = get(d, i);
    return prev * next <= 0 ? 0 : (prev + next) / 2;
  });
  // Fritsch-Carlson: clamp tangents so the curve never overshoots its neighbours.
  for (let i = 0; i < n - 1; i++) {
    const di = get(d, i);
    if (di === 0) {
      m[i] = 0;
      m[i + 1] = 0;
      continue;
    }
    const a = get(m, i) / di;
    const b = get(m, i + 1) / di;
    const h = a * a + b * b;
    if (h > 9) {
      const t = 3 / Math.sqrt(h);
      m[i] = t * a * di;
      m[i + 1] = t * b * di;
    }
  }
  let path = `M${first.x},${first.y}`;
  for (let i = 0; i < n - 1; i++) {
    const a = get(p, i);
    const b = get(p, i + 1);
    const h = (b.x - a.x) / 3;
    path += `C${a.x + h},${a.y + get(m, i) * h} ${b.x - h},${b.y - get(m, i + 1) * h} ${b.x},${b.y}`;
  }
  return path;
}

const DAY = 86_400_000;
export function segments<T extends { day: string }>(points: T[]): T[][] {
  const out: T[][] = [];
  for (const pt of points) {
    const run = out.at(-1);
    const last = run?.at(-1);
    if (run && last && Date.parse(pt.day) - Date.parse(last.day) === DAY) run.push(pt);
    else out.push([pt]);
  }
  return out;
}

const STEPS = [2, 4, 6, 8, 10, 20, 30, 40, 50, 60, 80, 100];
export function niceMax(max: number): number {
  const step = STEPS.find((s) => s >= max);
  if (step) return step;
  const mag = 10 ** Math.floor(Math.log10(max));
  return [1, 2, 4, 6, 8, 10].map((k) => k * mag).find((s) => s >= max) ?? 20 * mag;
}
export const ticks = (max: number) => [0, max / 2, max];

// ---- layout and text helpers for LineChart.tsx ----
export type Series = { label: string; points: { day: string; value: number }[] };
export type Layout = { W: number; H: number; padL: number; padR: number; padT: number; padB: number };

/** Pixel layout; `labels` leaves room on the right for end-of-line labels. */
export function layout(variant: "spark" | "full", W: number, labels = false): Layout {
  return variant === "full"
    ? { W, H: 150, padL: 26, padR: labels ? 32 : 10, padT: 10, padB: 20 }
    : { W, H: 36, padL: 2, padR: 6, padT: 4, padB: 3 };
}
export const xAt = (i: number, n: number, l: Layout) =>
  n < 2 ? l.W - l.padR : l.padL + ((l.W - l.padL - l.padR) * i) / (n - 1);
export const yAt = (v: number, max: number, l: Layout) => l.padT + (l.H - l.padT - l.padB) * (1 - v / max);
export const indexAt = (px: number, n: number, l: Layout) =>
  n < 2 ? 0 : Math.max(0, Math.min(n - 1, Math.round(((px - l.padL) / (l.W - l.padL - l.padR)) * (n - 1))));
/** Tooltip left edge within its tile: right of the cursor, never past either edge. */
export const tipLeft = (x: number, tipW: number, tileW: number) => Math.max(0, Math.min(x + 8, tileW - tipW - 6));

/** Every day from the earliest to the latest point of any series. */
export function axisDays(series: Series[]): string[] {
  const all = series.flatMap((s) => s.points.map((p) => Date.parse(p.day)));
  if (all.length === 0) return [];
  const lo = Math.min(...all);
  const hi = Math.max(...all);
  return Array.from({ length: Math.round((hi - lo) / DAY) + 1 }, (_, i) => new Date(lo + i * DAY).toISOString().slice(0, 10));
}

export const fmtDay = (day: string, year = false) => new Date(Date.parse(day)).toLocaleDateString("en-GB", { day: "numeric", month: "short", ...(year && { year: "numeric" }), timeZone: "UTC" });
export const dayLabel = (day: string, today: string, year = false) => (day === today ? "Today" : fmtDay(day, year));
/** True when the axis crosses a year boundary, so labels need the year. */
export const spansYears = (days: string[]) => days.length > 1 && days[0]?.slice(0, 4) !== days.at(-1)?.slice(0, 4);
/** What to show instead of a chart: only when there is no point at all. One point
 *  (the live value minutes after install) already draws, as a flat line (#238). */
export function emptyNote(series: Series[]): string | null {
  return axisDays(series).length === 0 ? "No data yet" : null;
}
/** A caption under the chart while history is under two days, else null. */
export function collectingNote(series: Series[]): string | null {
  const [first] = axisDays(series);
  if (first === undefined) return null;
  return Math.max(...series.map((s) => s.points.length)) < 2 ? `Collecting since ${fmtDay(first)}` : null;
}
/** Pixel points of one run of consecutive days. On a single-day axis there is no
 *  width to span, so the one point becomes a flat line across the plot. */
export function runPoints(run: { day: string; value: number }[], index: Map<string, number>, n: number, max: number, l: Layout): Pt[] {
  const [only] = run;
  if (n < 2 && only) {
    const y = yAt(only.value, max, l);
    return [{ x: l.padL, y }, { x: l.W - l.padR, y }];
  }
  return run.map((p) => ({ x: xAt(index.get(p.day) ?? 0, n, l), y: yAt(p.value, max, l) }));
}
/** A hover index that still points at a day after the series shrank. */
export const clampIndex = (i: number | null, n: number) => (i === null || n === 0 ? null : Math.min(i, n - 1));

export function ariaLabel(series: Series[]): string {
  const days = axisDays(series);
  const first = days[0];
  const last = days.at(-1);
  if (first === undefined || last === undefined) return `${series.map((s) => s.label).join(", ")}: no data`;
  const range = `${fmtDay(first)} to ${fmtDay(last)}`;
  const latest = (s: Series) => s.points.at(-1)?.value ?? "none";
  const [only] = series;
  return series.length === 1 && only ? `${only.label}: ${range}, now ${latest(only)}` : `${series.map((s) => `${s.label} ${latest(s)}`).join(", ")}: ${range}`;
}

/** Rows of day then one value per series ("–" for a missing day). */
export function tableRows(series: Series[]): string[][] {
  const by = series.map((s) => new Map(s.points.map((p) => [p.day, p.value])));
  return axisDays(series).map((day) => [day, ...by.map((m) => String(m.get(day) ?? "–"))]);
}

/** Moves end labels apart so they are at least `gap` pixels from each other, keeping their order. */
export function spreadLabels(ys: number[], gap: number): number[] {
  const order = ys.map((_, i) => i).sort((a, b) => (ys[a] ?? 0) - (ys[b] ?? 0));
  let groups = order.map((i) => ({ ids: [i], mid: ys[i] ?? 0 }));
  for (let merged = true; merged; ) {
    merged = false;
    const next: typeof groups = [];
    for (const g of groups) {
      const prev = next.at(-1);
      if (prev && g.mid - gap * (g.ids.length - 1) / 2 < prev.mid + gap * (prev.ids.length - 1) / 2 + gap) {
        const ids = [...prev.ids, ...g.ids];
        const sum = ids.reduce((t, i) => t + (ys[i] ?? 0), 0);
        next[next.length - 1] = { ids, mid: sum / ids.length };
        merged = true;
      } else next.push(g);
    }
    groups = next;
  }
  const out = [...ys];
  for (const g of groups) g.ids.forEach((id, j) => { out[id] = g.mid + (j - (g.ids.length - 1) / 2) * gap; });
  return out;
}
