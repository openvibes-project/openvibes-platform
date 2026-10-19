// Helpers the demo server's areas share: responses, paging, ranking and storage.
export const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
export const problem = (status: number, code: string, title: string, extra: Record<string, unknown> = {}) =>
  new Response(JSON.stringify({ status, code, title, ...extra, request_id: `demo-${Date.now().toString(36)}` }), {
    status, headers: { "content-type": "application/problem+json" },
  });

export function page<T>(items: readonly T[], query: URLSearchParams, fallback = 50) {
  const limit = Number(query.get("limit") ?? fallback) || fallback;
  const offset = Number(atob(query.get("cursor") ?? "") || 0) || 0;
  const slice = items.slice(offset, offset + limit);
  const next = offset + limit < items.length ? btoa(String(offset + limit)) : null;
  return { items: slice, next_cursor: next };
}

/** The real API's `MAX_PAGE_SIZE` (crates/openvibes-console/src/http/pagination.rs). */
export const MAX_PAGE = 100;

export const severityRank: Record<string, number> = { critical: 0, important: 1, high: 1, moderate: 2, medium: 2, low: 3, unrated: 4 };

/** Browser storage for demo state, when there is a browser; never required. */
export function browserPersistence(key: string) {
  if (typeof localStorage === "undefined") return undefined;
  return {
    load: () => { try { return JSON.parse(localStorage.getItem(key) ?? "null") as unknown; } catch { return undefined; } },
    save: (state: unknown) => { try { localStorage.setItem(key, JSON.stringify(state)); } catch { /* the demo still works without storage */ } },
  };
}
