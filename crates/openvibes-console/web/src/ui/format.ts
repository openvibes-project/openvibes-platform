const units: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31_536_000_000], ["month", 2_592_000_000], ["week", 604_800_000],
  ["day", 86_400_000], ["hour", 3_600_000], ["minute", 60_000],
];
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto", style: "short" });
const absolute = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const day = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

export const capitalise = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

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
  open: "Open", mitigated: "Mitigated",
  accepted_risk: "Accepted risk", false_positive: "False positive",
};

export const severityOrder: Record<string, number> = {
  critical: 0, high: 1, important: 1, medium: 2, moderate: 2, low: 3, unrated: 4,
};

/** A table's severity sort value: larger is more severe, so the first click (descending) starts with Critical; unknown is missing. */
export const severityRank = (severity: string | null | undefined): number | null =>
  severity != null && severity in severityOrder ? 4 - (severityOrder[severity] ?? 4) : null;

/** True when the time has passed (kept out of render bodies for the React compiler). */
export function isPast(value: string | number, now = Date.now()): boolean {
  return (typeof value === "number" ? value : Date.parse(value)) <= now;
}

export function within(value: string | number | null | undefined, ms: number, now = Date.now()): boolean {
  if (value == null) return false;
  return (typeof value === "number" ? value : Date.parse(value)) - now < ms;
}

/** Start of the UTC day `days` ago: a stable `since` for the whole day, so cached loads are reused. */
export function daysAgo(days: number, now = Date.now()): string {
  const today = new Date(now);
  return new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - days)).toISOString();
}

const auditRanges = [1, 7, 30, 365] as const;

/** The audit window chosen in the URL (`range` days, default 30). */
export function auditSince(params: URLSearchParams): string {
  const days = Number(params.get("range") ?? 30);
  return daysAgo((auditRanges as readonly number[]).includes(days) ? days : 30);
}

/** A vulnerability's title (#579): its package, then the first sentence
 * about the flaw, at most 140 characters. A title that already starts
 * with the package (an advisory's own title) is left as it is. */
export function vulnTitle(packages: readonly string[], title: string): string {
  const pkg = packages[0];
  // Many summaries open by saying what the product is ("Vim is an open
  // source text editor. Prior to…"): the flaw starts after that sentence.
  const told = title.replace(/^[^.]{1,80}? is an? [^.]*\.\s+(?=\S)/, "");
  const end = told.search(/\.(\s|$)/);
  let summary = end > 20 ? told.slice(0, end) : told;
  if (summary.length > 140) summary = `${summary.slice(0, 139).trimEnd()}…`;
  return pkg && !summary.toLowerCase().startsWith(pkg.toLowerCase()) ? `${pkg}: ${summary}` : summary;
}

/** Package names from a vulnerability row's `packages` (strings or objects with a `name`). */
export function packageNames(packages: unknown): string[] {
  if (!Array.isArray(packages)) return [];
  return packages.map((p: unknown) => (typeof p === "string" ? p : (p as { name?: unknown } | null)?.name)).filter((n): n is string => typeof n === "string" && n !== "");
}
