// The difference between two hosts' lists (#120), kept free of browser code.

/** What one side has that the other lacks, and keys present on both whose values differ. */
export function diff(a: ReadonlyMap<string, string>, b: ReadonlyMap<string, string>) {
  const onlyA = [...a.keys()].filter((k) => !b.has(k)).sort();
  const onlyB = [...b.keys()].filter((k) => !a.has(k)).sort();
  const changed = [...a.keys()].filter((k) => b.has(k) && a.get(k) !== b.get(k)).sort();
  return { onlyA, onlyB, changed };
}
