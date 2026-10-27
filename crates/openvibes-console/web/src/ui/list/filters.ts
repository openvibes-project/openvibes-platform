// A list page's filters and the URL helpers behind the FilterBar. Filters
// live in the URL (one parameter each, plus `q` for the search), so a view
// can be bookmarked, shared and saved.
import type { SelectOption } from "../select";

/** One filter chip: its URL parameter, its name, and its values with how many rows each matches.
 * `chipOnly`: set from elsewhere (a host page's tile), so drawn only while chosen. */
export type ListFilter = { param: string; label: string; values: readonly { value: string; label: string; count: number; hint?: string }[]; chipOnly?: boolean };

/** Parameters that order the list rather than filter it: Clear all keeps them. */
const ORDER = new Set(["sort", "dir"]);
/** The page shown (`offset`): not a filter, not saved in a view; any change of filter or order starts again at the first page. */
export const PAGE = "offset";

/** The values of a filter as Select options, the count beside each label. */
export const valueOptions = (filter: ListFilter): SelectOption[] =>
  filter.values.map((v) => ({ value: v.value, label: v.label, hint: v.hint ?? v.count.toLocaleString() }));

/** The filters with a value chosen, as chips ("Status: Online"); a value the list no longer offers shows as is. */
export function chosenFilters(filters: readonly ListFilter[], params: URLSearchParams): { param: string; text: string }[] {
  return filters.flatMap((f) => {
    const value = params.get(f.param);
    if (!value) return [];
    return [{ param: f.param, text: `${f.label}: ${f.values.find((v) => v.value === value)?.label ?? value}` }];
  });
}

/** Whether anything but the order is set: what Clear all and Save view act on. */
export const hasFilters = (params: URLSearchParams) => [...params.keys()].some((k) => !ORDER.has(k) && k !== PAGE);

/** Clear all: every parameter but the order. */
export const clearAllChanges = (params: URLSearchParams): Record<string, null> =>
  Object.fromEntries([...params.keys()].filter((k) => !ORDER.has(k)).map((k) => [k, null]));

/** The query a saved view stores: every parameter but the page, sorted, so equal views compare equal. */
export function viewQuery(params: URLSearchParams): string {
  const sorted = new URLSearchParams(params);
  sorted.delete(PAGE);
  sorted.sort();
  return sorted.toString();
}

/** Applying a saved view: its parameters replace all of today's; only the
 * page's filters, `q`, `sort` and `dir` are taken from it (a view saved
 * before a filter was dropped does not set a parameter nothing reads). */
export function applyViewChanges(params: URLSearchParams, query: string, filters: readonly ListFilter[]): Record<string, string | null> {
  const known = new Set(["q", ...ORDER, ...filters.map((f) => f.param)]);
  const changes: Record<string, string | null> = Object.fromEntries([...params.keys()].map((k) => [k, null]));
  for (const [k, v] of new URLSearchParams(query)) if (known.has(k)) changes[k] = v;
  return changes;
}

/** Calls `fn` with the last value `ms` after the last `set`; `flush` calls it now. */
export function debounce<T>(fn: (value: T) => void, ms: number) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let waiting: { value: T } | undefined;
  const flush = () => {
    clearTimeout(timer);
    const w = waiting;
    waiting = undefined;
    if (w) fn(w.value);
  };
  return {
    set(value: T) { waiting = { value }; clearTimeout(timer); timer = setTimeout(flush, ms); },
    flush,
    cancel() { clearTimeout(timer); waiting = undefined; },
  };
}
