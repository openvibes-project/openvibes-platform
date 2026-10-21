// Agent version order for the demo: the twin of platform-store's
// version_order.rs and the SQL console_version_parts / console_version_older
// (migration 57, plan ruling 7). Numeric segments compared (trailing zero
// segments dropped, then the arrays compared as SQL compares int[]); a
// pre-release is older than its release; build metadata ignored.

/** The numeric segments (trailing zeros dropped) and whether it is a
 * pre-release; null when empty or any segment is not 1–9 digits. */
function parts(version: string): [number[], boolean] | null {
  const plain = version.split("+")[0] ?? "";
  const dash = plain.indexOf("-");
  const core = dash < 0 ? plain : plain.slice(0, dash);
  if (!/^\d{1,9}(\.\d{1,9})*$/.test(core)) return null;
  return [core.replace(/(\.0+)+$/, "").split(".").map(Number), dash >= 0];
}

/** int[] order: element by element, then the shorter first. */
function arrays(a: number[], b: number[]): number {
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

/** Whether `version` is older than `latest`; null when either is unknown. */
export function older(version: string, latest: string): boolean | null {
  const a = parts(version);
  const b = parts(latest);
  if (!a || !b) return null;
  const d = arrays(a[0], b[0]);
  return d !== 0 ? d < 0 : a[1] && !b[1];
}

/** The list's version sort in direction `dir` (1 or -1), as the SQL ORDER BY:
 * unknown versions last either way, a pre-release before its release. */
export function compareVersions(x: string | null | undefined, y: string | null | undefined, dir = 1): number {
  const a = x == null ? null : parts(x);
  const b = y == null ? null : parts(y);
  if (!a || !b) return (a ? 0 : 1) - (b ? 0 : 1);
  return dir * (arrays(a[0], b[0]) || Number(b[1]) - Number(a[1]));
}
