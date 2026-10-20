// A list page's filters and the URL helpers behind the FilterBar. Filters
// live in the URL (one parameter each, plus `q` for the search), so a view
// can be bookmarked, shared and saved.
import type { SelectOption } from "../select";

/** One filter chip: its URL parameter, its name, and its values with how many rows each matches. */
export type ListFilter = { param: string; label: string; values: readonly { value: string; label: string; count: number }[] };

/** Parameters that order the list rather than filter it: Clear all keeps them. */
const ORDER = new Set(["sort", "dir"]);

/** The values of a filter as Select options, the count beside each label. */
export const valueOptions = (filter: ListFilter): SelectOption[] =>
  filter.values.map((v) => ({ value: v.value, label: v.label, hint: v.count.toLocaleString() }));

/** The filters with a value chosen, as chips ("Status: Online"); a value the list no longer offers shows as is. */
export function chosenFilters(filters: readonly ListFilter[], params: URLSearchParams): { param: string; text: string }[] {
  return filters.flatMap((f) => {
    const value = params.get(f.param);
    if (!value) return [];
    return [{ param: f.param, text: `${f.label}: ${f.values.find((v) => v.value === value)?.label ?? value}` }];
  });
}

/** Whether anything but the order is set: what Clear all and Save view act on. */
export const hasFilters = (params: URLSearchParams) => [...params.keys()].some((k) => !ORDER.has(k));

/** Clear all: every parameter but the order. */
export const clearAllChanges = (params: URLSearchParams): Record<string, null> =>
  Object.fromEntries([...params.keys()].filter((k) => !ORDER.has(k)).map((k) => [k, null]));

/** The query a saved view stores: every parameter, sorted, so equal views compare equal. */
export function viewQuery(params: URLSearchParams): string {
  const sorted = new URLSearchParams(params);
  sorted.sort();
  return sorted.toString();
}

/** Applying a saved view: its parameters replace all of today's. */
export function applyViewChanges(params: URLSearchParams, query: string): Record<string, string | null> {
  const changes: Record<string, string | null> = Object.fromEntries([...params.keys()].map((k) => [k, null]));
  for (const [k, v] of new URLSearchParams(query)) changes[k] = v;
  return changes;
}
