// Row selection for bulk actions (triage v2, spec 2026-10-10-bulk-triage
// §3): single rows, a shift-click range, the rows on screen, or every row
// the current filter matches, up to MAX_SELECTION.
import { useEffect, useState } from "react";

/** Most rows one bulk action takes (the server's limit). */
export const MAX_SELECTION = 10_000;

/** `base` with every key between `from` and `to` (inclusive, in `keys`
 * order) set to `on`. */
export function selectRange(keys: readonly string[], from: number, to: number, base: ReadonlySet<string>, on: boolean): Set<string> {
  const next = new Set(base);
  const [lo, hi] = from <= to ? [from, to] : [to, from];
  for (const key of keys.slice(Math.max(0, lo), hi + 1)) {
    if (on) next.add(key); else next.delete(key);
  }
  return next;
}

/** The first MAX_SELECTION keys: "select all matching this filter". */
export function selectAll(keys: readonly string[]): Set<string> {
  return new Set(keys.slice(0, MAX_SELECTION));
}

/** A selection that empties whenever `reset` changes (the filter). */
export function useSelection(reset: string): [Set<string>, (next: Set<string>) => void] {
  const [state, setState] = useState<{ reset: string; selected: Set<string> }>({ reset, selected: new Set() });
  useEffect(() => {
    if (state.reset !== reset) setState({ reset, selected: new Set() });
  }, [reset, state.reset]);
  const selected = state.reset === reset ? state.selected : new Set<string>();
  return [selected, (next) => setState({ reset, selected: next })];
}
