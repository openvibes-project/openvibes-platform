/** Index after an arrow key, wrapping at both ends. */
export function wrapStep(index: number, delta: 1 | -1, count: number): number {
  return (index + delta + count) % count;
}

/** Options plus, when `value` is not among them, an extra one for it (never silently dropped). */
export function withUnknown<T>(options: { value: T; label: string }[], value: T, unknownLabel: (v: T) => string) {
  return options.some((o) => o.value === value) ? options : [...options, { value, label: unknownLabel(value) }];
}
