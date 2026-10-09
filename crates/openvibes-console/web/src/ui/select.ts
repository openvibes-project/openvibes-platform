// Pure helpers behind Select (ui/Select.tsx): grouping, filtering, stepping, placement.
import { matches } from "./table";

export type SelectOption = { value: string; label: string; disabled?: boolean; hint?: string | undefined };
export type SelectGroup = { group: string; options: SelectOption[] };
export type Section = { group?: string; options: SelectOption[] };

/** Plain options become one heading-less section. */
export function toSections(options: SelectOption[] | SelectGroup[]): Section[] {
  const first = options[0];
  if (!first) return [];
  return "group" in first
    ? (options as SelectGroup[]).map((g) => ({ group: g.group, options: g.options }))
    : [{ options: options as SelectOption[] }];
}

export function filterSections(sections: Section[], query: string): Section[] {
  return sections
    .map((s) => ({ ...s, options: s.options.filter((o) => matches([o.label], query)) }))
    .filter((s) => s.options.length > 0);
}

export const enabledCount = (sections: Section[]) => sections.reduce((n, s) => n + s.options.filter((o) => !o.disabled).length, 0);
export const SEARCH_ABOVE = 8;

/** Next enabled index from `from` in direction `dir`, staying put at either end. */
export function step(flat: readonly SelectOption[], from: number, dir: 1 | -1): number {
  for (let i = from + dir; i >= 0 && i < flat.length; i += dir) if (!flat[i]?.disabled) return i;
  return from;
}

export const firstEnabled = (flat: readonly SelectOption[]) => flat.findIndex((o) => !o.disabled);

/** Fixed-position popup box: down unless under 220 px below and more room above; clamped to the viewport. */
export function placement(rect: { left: number; right: number; top: number; bottom: number }, viewport: { width: number; height: number }) {
  const gap = 4, edge = 8;
  const below = viewport.height - rect.bottom - edge - gap, above = rect.top - edge - gap;
  const up = below < 220 && above > below;
  const width = Math.min(rect.right - rect.left, viewport.width - 2 * edge);
  const left = Math.min(Math.max(edge, rect.left), viewport.width - edge - width);
  return up
    ? { left, width, bottom: viewport.height - rect.top + gap, maxHeight: Math.max(120, above) }
    : { left, width, top: rect.bottom + gap, maxHeight: Math.max(120, below) };
}
