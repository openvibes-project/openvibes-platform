// One filter catalogue per list: the views build their chip bars from it and
// the List widget editor offers the same filters. Runtime extras (compliance
// rule sets, counts) stay in the views and are not part of the catalogue.
import type { ListView } from "./rows";

export type FilterDef =
  | { param: string; label: string; kind: "flag"; value: string }
  | { param: string; label: string; kind: "choice"; values: { value: string; label: string }[] };

const choice = (param: string, label: string, values: [string, string][]): FilterDef => ({
  param, label, kind: "choice", values: values.map(([value, label]) => ({ value, label })),
});
const severities = (...names: string[]) => names.map((n): [string, string] => [n, n[0]?.toUpperCase() + n.slice(1)]);

export const LIST_FILTERS: Record<ListView, FilterDef[]> = {
  "/compliance": [
    { param: "state", label: "Include resolved", kind: "flag", value: "all" },
    choice("severity", "Severity", severities("critical", "high", "medium", "low")),
  ],
  "/vulnerabilities": [
    { param: "state", label: "Include resolved", kind: "flag", value: "all" },
    { param: "exploited", label: "Known exploited", kind: "flag", value: "true" },
    { param: "reboot", label: "Reboot needed", kind: "flag", value: "true" },
    { param: "nofix", label: "No fix yet", kind: "flag", value: "true" },
    { param: "lowconf", label: "Lower confidence", kind: "flag", value: "true" },
    choice("severity", "Severity", severities("critical", "important", "moderate", "low")),
  ],
  "/agents": [
    choice("status", "Status", [["active", "Online"], ["stale", "Stale"], ["imported", "Imported"], ["revoked", "Revoked"]]),
  ],
  "/audit": [
    { param: "result", label: "Failures", kind: "flag", value: "failure" },
    choice("range", "Range", [["1", "Last day"], ["7", "Last 7 days"], ["365", "Last 365 days"]]),
  ],
};

export const LIST_LABELS: Record<ListView, string> = {
  "/compliance": "Compliance findings", "/vulnerabilities": "Vulnerabilities", "/agents": "Hosts", "/audit": "Audit log",
};

export type Chip = { param: string; value: string; label: string; known: boolean };

/** The catalogue as the flat chips a view header shows (bare value labels), in catalogue order. */
export function filterChips(view: ListView): { label: string; param: string; value: string }[] {
  return LIST_FILTERS[view].flatMap((f) => f.kind === "flag"
    ? [{ label: f.label, param: f.param, value: f.value }]
    : f.values.map((v) => ({ label: v.label, param: f.param, value: v.value })));
}

function labelOf(view: ListView, param: string, value: string): string | undefined {
  const def = LIST_FILTERS[view].find((f) => f.param === param);
  if (!def) return undefined;
  if (def.kind === "flag") return def.value === value ? def.label : undefined;
  const v = def.values.find((x) => x.value === value);
  return v && `${def.label}: ${v.label}`;
}

/**
 * A query as chips in catalogue order. Each catalogue param holds one value: the first occurrence
 * with a known value is its chip; later duplicates and unknown params are plain (removable) chips.
 */
export function chipsOf(view: ListView, query: string): Chip[] {
  const seen = new Set<string>();
  const all = [...new URLSearchParams(query)].map(([param, value]): Chip => {
    const label = seen.has(param) ? undefined : labelOf(view, param, value);
    if (label !== undefined) seen.add(param);
    return { param, value, label: label ?? `${param}=${value}`, known: label !== undefined };
  });
  const order = (c: Chip) => (c.known ? LIST_FILTERS[view].findIndex((f) => f.param === c.param) : Infinity);
  return all.map((c, i) => [c, i] as const).sort(([a, i], [b, j]) => (order(a) === order(b) ? i - j : order(a) < order(b) ? -1 : 1)).map(([c]) => c);
}

export function queryOf(chips: Chip[]): string {
  return new URLSearchParams(chips.map((c) => [c.param, c.value] as [string, string])).toString();
}

/** Sets a catalogue filter, replacing the value that param already has. */
export function setFilter(view: ListView, query: string, param: string, value: string): string {
  const rest = chipsOf(view, query).filter((c) => !(c.known && c.param === param));
  return queryOf(chipsOf(view, queryOf([...rest, { param, value, label: "", known: true }])));
}

/**
 * Keeps unknown params, drops params that some other list filters on but this one does not,
 * or whose value this list does not offer.
 * The result is re-sorted into catalogue order and re-encoded, so it may differ from the input text.
 */
export function dropUnsupported(view: ListView, query: string): string {
  const others = new Set(Object.values(LIST_FILTERS).flat().map((f) => f.param));
  const kept = [...new URLSearchParams(query)].filter(([p, v]) => !others.has(p) || labelOf(view, p, v) !== undefined);
  return queryOf(chipsOf(view, new URLSearchParams(kept).toString()));
}
