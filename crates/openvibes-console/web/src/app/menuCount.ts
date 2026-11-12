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

/** What a dashboard breakdown counts, when its title does not say:
 * one per host, where the lists count checks and CVEs (#580). */
export function unitOf(source: string): string {
  if (source === "compliance") return "failing findings";
  if (source === "vulnerabilities") return "on hosts";
  return "";
}

/** The menu count's title and label: "5 failing checks", "3 alarms". The
 * menu counts what the list it opens counts (#580). */
export function countTitle(path: string, count: string, label: string): string {
  return `${count} ${path === "/compliance" ? "failing checks" : label.toLowerCase()}`;
}
