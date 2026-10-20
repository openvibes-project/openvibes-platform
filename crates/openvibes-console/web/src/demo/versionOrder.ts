// Agent version order for the demo: the twin of platform-store's
// version_order.rs and the SQL console_version_older / console_version_parts
// (plan ruling 7). Numeric segments compared, the shorter padded with zeros;
// a pre-release is older than its release; build metadata ignored.

/** The numeric segments and whether it is a pre-release; null when empty or any segment is not 1–9 digits. */
function parts(version: string): [number[], boolean] | null {
  const plain = version.split("+")[0] ?? "";
  const dash = plain.indexOf("-");
  const core = dash < 0 ? plain : plain.slice(0, dash);
  const segments = core.split(".");
  if (!segments.every((s) => /^\d{1,9}$/.test(s))) return null;
  return [segments.map(Number), dash >= 0];
}

/** Whether `version` is older than `latest`; null when either is unknown. */
export const older = (version: string, latest: string): boolean | null =>
  parts(version) && parts(latest) ? compareVersions(version, latest) < 0 : null;

/** Ascending order, as the list's version sort: unknown versions last. */
export function compareVersions(x: string | null | undefined, y: string | null | undefined): number {
  const a = x == null ? null : parts(x);
  const b = y == null ? null : parts(y);
  if (!a || !b) return (a ? 0 : 1) - (b ? 0 : 1);
  for (let i = 0; i < Math.max(a[0].length, b[0].length); i += 1) {
    const d = (a[0][i] ?? 0) - (b[0][i] ?? 0);
    if (d !== 0) return d;
  }
  return Number(b[1]) - Number(a[1]);
}
