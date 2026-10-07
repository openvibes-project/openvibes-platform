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
