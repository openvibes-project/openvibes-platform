// Lists: each person's saved views and hidden columns per list page, as
// src/lists/saved_views.rs answers them (codes, caps, case-blind names).
import type { ListColumns, SavedView } from "../../api/types";
import type { DemoContext } from "../context";
import { browserPersistence, json, problem } from "../http";

/** The list pages and the columns each may hide (src/lists/mod.rs); Host never. */
const HIDEABLE: Record<string, readonly string[]> = { hosts: ["os", "groups", "labels", "problems", "heartbeat", "agent"] };
const MAX_VIEWS = 50;
const CONTROL = /\p{Cc}/u;

const validName = (name: string) => { const n = [...name].length; return n >= 1 && n <= 60 && !CONTROL.test(name); };
const validQuery = (query: string) => [...query].length <= 1000 && !CONTROL.test(query);
/** The server's ORDER BY lower(name), name, view_id: plain order, no locale. */
const byUnits = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const sameName = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
const invalid = (code: string, field: string, message: string) =>
  problem(422, code, message, { field_errors: [{ field, code: "invalid", message }] });
/** A list page (an own key: "constructor" is not one). */
const known = (page: string) => Object.hasOwn(HIDEABLE, page);
const pageNotFound = () => problem(404, "list_page_not_found", "No such list page");

export function validView(value: unknown): value is SavedView {
  const v = value as Partial<SavedView> | null;
  return typeof v === "object" && v !== null && typeof v.id === "string" && typeof v.page === "string" && known(v.page)
    && typeof v.name === "string" && v.name === v.name.trim() && validName(v.name)
    && typeof v.query === "string" && validQuery(v.query) && typeof v.created_at === "string";
}

export function registerListRoutes(ctx: DemoContext) {
  const { route, me, iso } = ctx;
  // Kept in the browser per person, so a reload keeps them; checked on load, as storage could hold anything.
  const store = browserPersistence(`openvibes.v2.demo.lists.${me}`);
  const loaded = store?.load() as { views?: unknown; hidden?: unknown } | null | undefined;
  const views: SavedView[] = [];
  for (const v of Array.isArray(loaded?.views) ? loaded.views : []) {
    if (!validView(v)) continue;
    const onPage = views.filter((w) => w.page === v.page);
    if (onPage.length < MAX_VIEWS && !onPage.some((w) => sameName(w.name, v.name))) views.push(v);
  }
  const hidden: Record<string, string[]> = {};
  const storedHidden = (loaded?.hidden ?? {}) as Record<string, unknown>;
  for (const [page, allowed] of Object.entries(HIDEABLE)) {
    const keys = storedHidden[page];
    hidden[page] = [...new Set(Array.isArray(keys) ? keys.filter((k): k is string => typeof k === "string" && allowed.includes(k)) : [])];
  }
  const save = () => store?.save({ views, hidden });

  route("GET", "/api/v1/saved-views", null, (_, query) => {
    const page = query.get("page") ?? "";
    if (!known(page)) return pageNotFound();
    const items = views.filter((v) => v.page === page)
      .sort((a, b) => byUnits(a.name.toLowerCase(), b.name.toLowerCase()) || byUnits(a.name, b.name) || byUnits(a.id, b.id));
    return json({ items });
  });
  route("POST", "/api/v1/saved-views", null, (_, __, body) => {
    const { page, name: raw, query } = body;
    if (typeof page !== "string" || typeof raw !== "string" || typeof query !== "string") return problem(400, "invalid_request", "The request is invalid");
    if (!known(page)) return pageNotFound();
    const name = raw.trim();
    if (!validName(name)) return invalid("invalid_saved_view", "name", "The name must be 1 to 60 characters");
    if (!validQuery(query)) return invalid("invalid_saved_view", "query", "The view is too long to save");
    const onPage = views.filter((v) => v.page === page);
    if (onPage.length >= MAX_VIEWS) return problem(409, "too_many_views", "You can keep at most 50 views on this page");
    if (onPage.some((v) => sameName(v.name, name))) return problem(409, "view_name_taken", "You already have a view with that name");
    const view: SavedView = { id: crypto.randomUUID(), page, name, query, created_at: iso() };
    views.push(view);
    save();
    return json(view, 201);
  });
  route("DELETE", "/api/v1/saved-views/{id}", null, (params) => {
    const index = views.findIndex((v) => v.id === params.id);
    if (index < 0) return problem(404, "saved_view_not_found", "No such saved view");
    views.splice(index, 1);
    save();
    return new Response(null, { status: 204 });
  });
  route("GET", "/api/v1/list-columns/{page}", null, (params) => {
    const page = params.page ?? "";
    return known(page) ? json({ hidden: hidden[page] ?? [] } satisfies ListColumns) : pageNotFound();
  });
  route("PUT", "/api/v1/list-columns/{page}", null, (params, _, body) => {
    const page = params.page ?? "";
    const allowed = known(page) ? HIDEABLE[page] : undefined;
    if (!allowed) return pageNotFound();
    const keys = body.hidden;
    if (!Array.isArray(keys) || !keys.every((k) => typeof k === "string")) return problem(400, "invalid_request", "The request is invalid");
    if (keys.includes("host")) return invalid("invalid_columns", "hidden", "The Host column can't be hidden");
    if (keys.length > 32 || keys.some((k, i) => !allowed.includes(k) || keys.indexOf(k) !== i)) return invalid("invalid_columns", "hidden", "Unknown or repeated column");
    hidden[page] = keys;
    save();
    return json({ hidden: keys } satisfies ListColumns);
  });
}
