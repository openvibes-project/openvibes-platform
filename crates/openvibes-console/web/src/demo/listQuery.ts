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
