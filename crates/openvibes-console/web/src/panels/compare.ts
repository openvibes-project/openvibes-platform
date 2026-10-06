// The difference between two hosts' lists (#120), kept free of browser code.

/** What one side has that the other lacks, and keys present on both whose values differ. */
export function diff(a: ReadonlyMap<string, string>, b: ReadonlyMap<string, string>) {
  const onlyA = [...a.keys()].filter((k) => !b.has(k)).sort((x, y) => x.localeCompare(y));
  const onlyB = [...b.keys()].filter((k) => !a.has(k)).sort((x, y) => x.localeCompare(y));
  const changed = [...a.keys()].filter((k) => b.has(k) && a.get(k) !== b.get(k)).sort((x, y) => x.localeCompare(y));
  return { onlyA, onlyB, changed };
}

export type Kind = "onlyA" | "onlyB" | "changed";
export type DiffRow = { key: string; kind: Kind };

/** The differences as one list: only on A, only on B, then changed (each sorted). */
export function rows(a: ReadonlyMap<string, string>, b: ReadonlyMap<string, string>): DiffRow[] {
  const d = diff(a, b);
  return [
    ...d.onlyA.map((key) => ({ key, kind: "onlyA" as const })),
    ...d.onlyB.map((key) => ({ key, kind: "onlyB" as const })),
    ...d.changed.map((key) => ({ key, kind: "changed" as const })),
  ];
}

/** Rows of the chosen kind (all when none) whose key contains the text, ignoring case. */
export function filterRows(list: readonly DiffRow[], text: string, kind: Kind | undefined): DiffRow[] {
  const needle = text.trim().toLowerCase();
  return list.filter((r) => (!kind || r.kind === kind) && (!needle || r.key.toLowerCase().includes(needle)));
}
