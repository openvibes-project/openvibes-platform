// Synthetic daily history for /api/v1/metrics/history: a deterministic walk
// seeded by the metric id that ends on today's live value.
const DAY = 86_400_000;

function seed(text: string): number {
  return [...text].reduce((h, c) => Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0, 2166136261);
}

/** `days` points ending on `now`'s UTC day, oldest first; the last value is `current`. */
export function demoHistory(metric: string, days: number, current: number, now = Date.now()): { day: string; value: number }[] {
  let state = seed(metric);
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  // Walk backwards from today: small steps scaled to the value, never below 0.
  const values = [current];
  for (let i = 1; i < days; i++) {
    const prev = values[0] ?? current;
    const step = Math.round((next() - 0.5) * 2 * Math.max(1, Math.sqrt(Math.max(prev, current))));
    values.unshift(next() < 0.55 ? prev : Math.max(0, prev + step));
  }
  const today = Math.floor(now / DAY) * DAY;
  return values.map((value, i) => ({ day: new Date(today - (values.length - 1 - i) * DAY).toISOString().slice(0, 10), value }));
}
