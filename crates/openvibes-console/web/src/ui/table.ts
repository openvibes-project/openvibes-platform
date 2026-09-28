export type SortValue = string | number | boolean | null | undefined;
export type Direction = "asc" | "desc";

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

/** Stable sort by `key`; missing values always sort last. */
export function sortRows<T>(rows: readonly T[], key: (row: T) => SortValue, direction: Direction): T[] {
  const sign = direction === "asc" ? 1 : -1;
  return rows
    .map((row, index) => ({ row, index, value: key(row) }))
    .sort((a, b) => {
      const missingA = a.value == null || a.value === "";
      const missingB = b.value == null || b.value === "";
      if (missingA || missingB) return missingA === missingB ? a.index - b.index : missingA ? 1 : -1;
      const order = typeof a.value === "string" || typeof b.value === "string"
        ? collator.compare(String(a.value), String(b.value))
        : Number(a.value) - Number(b.value);
      return order === 0 ? a.index - b.index : order * sign;
    })
    .map(({ row }) => row);
}

/** True when every word of `filter` occurs in one of `fields`. */
export function matches(fields: readonly (string | null | undefined)[], filter: string): boolean {
  const words = filter.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return true;
  const haystack = fields.filter(Boolean).join(" \u0000 ").toLowerCase();
  return words.every((word) => haystack.includes(word));
}
