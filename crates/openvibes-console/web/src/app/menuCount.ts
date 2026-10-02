// The number beside a menu item (#117).

/** A menu count: nothing at 0, "99+" beyond 99 (#117). */
export function menuCount(n: number | undefined, more = false): string | undefined {
  if (!n) return undefined;
  return more || n > 99 ? "99+" : String(n);
}
