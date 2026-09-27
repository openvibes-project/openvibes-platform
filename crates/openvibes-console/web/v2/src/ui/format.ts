const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31_536_000_000], ["month", 2_592_000_000], ["week", 604_800_000],
  ["day", 86_400_000], ["hour", 3_600_000], ["minute", 60_000],
];
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto", style: "short" });
const absolute = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const day = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

/** "4 min ago", "in 3 days"; "just now" under a minute. */
export function ago(value: string | number | null | undefined, now = Date.now()): string {
  if (value == null) return "never";
  const ms = typeof value === "number" ? value : Date.parse(value);
  if (Number.isNaN(ms)) return "unknown";
  const delta = ms - now;
  for (const [unit, size] of units) {
    if (Math.abs(delta) >= size) return relative.format(Math.round(delta / size), unit);
  }
  return "just now";
}

export function when(value: string | number | null | undefined): string {
  if (value == null) return "—";
  const ms = typeof value === "number" ? value : Date.parse(value);
  return Number.isNaN(ms) ? "—" : absolute.format(ms);
}

export function date(value: string | number | null | undefined): string {
  if (value == null) return "—";
  const ms = typeof value === "number" ? value : Date.parse(value);
  return Number.isNaN(ms) ? "—" : day.format(ms);
}

export const count = (value: number) => value.toLocaleString();
export const pct = (value: number | null | undefined, digits = 1) =>
  value == null ? "—" : `${(value * 100).toFixed(digits)}%`;

export function plural(n: number, one: string, many = `${one}s`) {
  return `${count(n)} ${n === 1 ? one : many}`;
}

export const triageLabel: Record<string, string> = {
  open: "Open", investigating: "Investigating", mitigated: "Mitigated",
  accepted_risk: "Accepted risk", false_positive: "False positive",
};

export const severityOrder: Record<string, number> = {
  critical: 0, high: 1, important: 1, medium: 2, moderate: 2, low: 3, unrated: 4,
};

export function shortHost(hostname: string | null | undefined, fallback: string): string {
  return hostname ?? fallback;
}

/** True when the time has passed (kept out of render bodies for the React compiler). */
export function isPast(value: string | number, now = Date.now()): boolean {
  return (typeof value === "number" ? value : Date.parse(value)) <= now;
}

export function within(value: string | number | null | undefined, ms: number, now = Date.now()): boolean {
  if (value == null) return false;
  return (typeof value === "number" ? value : Date.parse(value)) - now < ms;
}
