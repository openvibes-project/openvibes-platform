/** Index after an arrow key, wrapping at both ends. */
export function wrapStep(index: number, delta: 1 | -1, count: number): number {
  return (index + delta + count) % count;
}

/** Options plus, when `value` is not among them, an extra one for it (never silently dropped). */
export function withUnknown<O extends { value: unknown; label: string }>(options: O[], value: O["value"], unknownLabel: (v: O["value"]) => string): O[] {
  return options.some((o) => o.value === value) ? options : [...options, { value, label: unknownLabel(value) } as O];
}

/** The index a key moves to (arrows wrap, Home and End jump), or null when the key is not ours. */
export function keyTarget(key: string, current: number, count: number): number | null {
  if (key === "ArrowRight" || key === "ArrowDown") return wrapStep(current, 1, count);
  if (key === "ArrowLeft" || key === "ArrowUp") return wrapStep(current, -1, count);
  if (key === "Home") return 0;
  if (key === "End") return count - 1;
  return null;
}
