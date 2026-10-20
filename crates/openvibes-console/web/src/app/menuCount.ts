// The number beside a menu item (#117).

/** A menu count: nothing at 0, "99+" beyond 99 (#117). */
export function menuCount(n: number | undefined, more = false): string | undefined {
  if (!n) return undefined;
  return more || n > 99 ? "99+" : String(n);
}

/** The Alarm suppressions count: waiting requests the viewer can decide. */
export function waitingToDecide(items: readonly { status: string; can_decide: boolean }[] | undefined): string | undefined {
  return menuCount(items?.filter((s) => s.status === "waiting" && s.can_decide).length);
}
