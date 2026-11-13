import { hasControl } from "./hostGroups";
import { problem } from "./http";

/**
 * The checks every demo list makes on its query (the server's 400 invalid_query):
 * closed-set parameters, bounded text, the demo's id shapes (grp-…, u-…, standing in
 * for the server's UUID check) and the paging window. Returns the 400, or null.
 */
export function listQueryError(query: URLSearchParams, title: string, closed: [string, string[]][], texts: [string, number][]): Response | null {
  const get = (k: string) => query.get(k) || null;
  const invalid = (field: string) => problem(400, "invalid_query", title,
    { field_errors: [{ field, code: "invalid", message: `The ${field} parameter is invalid` }] });
  for (const [field, allowed] of closed) {
    const v = get(field);
    if (v !== null && !allowed.includes(v)) return invalid(field);
  }
  for (const [field, max] of texts) {
    const v = get(field);
    if (v !== null && ([...v].length > max || hasControl(v))) return invalid(field);
  }
  const group = get("group");
  if (group !== null && !/^grp-[a-z0-9-]{1,64}$/.test(group)) return invalid("group");
  const assignee = get("assignee");
  if (assignee !== null && assignee !== "me" && assignee !== "unassigned" && !/^u-[a-z0-9-]{1,32}$/.test(assignee)) return invalid("assignee");
  const offset = Number(get("offset") ?? 0);
  const limit = Number(get("limit") ?? 50);
  if (!Number.isInteger(offset) || offset < 0 || offset > 100_000) return invalid("offset");
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) return invalid("limit");
  return null;
}

const HOST_STATES = ["open", "mitigated", "accepted_risk", "false_positive", "resolved", "passing"];

/** A detail page's Hosts `sort` and `dir` (host_sort.rs): the invalid parameter, or null. */
export function hostSortError(query: URLSearchParams, hasState: boolean): string | null {
  const sort = query.get("sort") || "host";
  if (!["host", "date", ...(hasState ? ["state"] : [])].includes(sort)) return "sort";
  return ["", "asc", "desc"].includes(query.get("dir") ?? "") ? null : "dir";
}

/** `rows`, already by host name, in the query's sort: state (open first) or `date`, missing last, ties by host name. */
export function sortHosts<T>(rows: readonly T[], query: URLSearchParams, date: (row: T) => string | null | undefined, state?: (row: T) => string): T[] {
  const sign = query.get("dir") === "desc" ? -1 : 1;
  const sort = query.get("sort") || "host";
  if (sort === "host") return sign === 1 ? [...rows] : [...rows].reverse();
  const key = (row: T) => {
    if (sort === "date") return date(row) ?? null;
    const at = state ? HOST_STATES.indexOf(state(row)) : -1;
    return at < 0 ? null : at;
  };
  return rows.map((row, i) => ({ row, i, k: key(row) }))
    .sort((a, b) => (a.k === b.k ? a.i - b.i : a.k === null ? 1 : b.k === null ? -1 : (a.k < b.k ? -1 : 1) * sign))
    .map((x) => x.row);
}
