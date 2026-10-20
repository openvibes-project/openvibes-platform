// Saved views and hidden columns, kept per person and page by the console
// (/api/v1/saved-views, /api/v1/list-columns/{page}).
import { ApiError, invalidate, prime, request, useResource } from "../../api/client";
import type { ListColumns, SavedView, SavedViewList } from "../../api/types";
import { toast } from "../toast";
import { viewQuery } from "./filters";

const viewsPath = (page: string) => `/api/v1/saved-views?page=${encodeURIComponent(page)}`;
const columnsPath = (page: string) => `/api/v1/list-columns/${encodeURIComponent(page)}`;

/** The person's views on `page`, by name. */
export function useSavedViews(page: string): SavedView[] {
  return useResource<SavedViewList>(viewsPath(page)).data?.items ?? [];
}

/** The column keys the person hides on `page`; undefined until loaded. */
export function useHiddenColumns(page: string): string[] | undefined {
  return useResource<ListColumns>(columnsPath(page)).data?.hidden;
}

export async function saveView(page: string, name: string, query: string): Promise<SavedView> {
  const view = await request<SavedView>("POST", "/api/v1/saved-views", { page, name, query });
  invalidate(viewsPath(page));
  return view;
}

export async function deleteView(page: string, id: string): Promise<void> {
  await request("DELETE", `/api/v1/saved-views/${encodeURIComponent(id)}`);
  invalidate(viewsPath(page));
}

export async function setHiddenColumns(page: string, hidden: string[]): Promise<ListColumns> {
  const saved = await request<ListColumns>("PUT", columnsPath(page), { hidden });
  prime(columnsPath(page), saved);
  return saved;
}

/** Hides a shown column or shows a hidden one. */
export const toggleHidden = (hidden: readonly string[], key: string) =>
  hidden.includes(key) ? hidden.filter((k) => k !== key) : [...hidden, key];

const SUFFIX = " (imported)";
/** At most `max` characters (code points, as the server counts), no outer spaces. */
const clip = (name: string, max = 60) => [...name.trim()].slice(0, max).join("").trimEnd();

const running = new Map<string, Promise<void>>();
const FINAL = new Set(["invalid_saved_view", "too_many_views", "view_name_taken"]);

/**
 * Moves the views a page kept in this browser (before saved views lived on
 * the console) to the console: `mapQuery` turns an old query into today's,
 * stored normalised (`viewQuery`) so the view shows as active. A name taken
 * by a different view is retried once as "name (imported)". One run per key
 * at a time (every mount calls this). The key is removed once every view is
 * saved, already there, or refused for good (invalid, too many, name taken
 * twice: one toast names those); a transient error keeps it for the next visit.
 */
export function importBrowserViews(page: string, legacyKey: string, mapQuery: (query: string) => string): Promise<void> {
  const active = running.get(legacyKey);
  if (active) return active;
  const run = importOnce(page, legacyKey, mapQuery).finally(() => running.delete(legacyKey));
  running.set(legacyKey, run);
  return run;
}

async function importOnce(page: string, legacyKey: string, mapQuery: (query: string) => string): Promise<void> {
  let old: unknown;
  try {
    const raw = localStorage.getItem(legacyKey);
    if (raw === null) return;
    old = JSON.parse(raw);
  } catch {
    old = undefined; // no storage, or not JSON: nothing to import
  }
  const views = Array.isArray(old) ? old.filter((v): v is { name: string; query: string } => typeof v?.name === "string" && typeof v?.query === "string") : [];
  const refused: string[] = [];
  let transient = false;
  try {
    const existing = views.length > 0 ? (await request<SavedViewList>("GET", viewsPath(page))).items : [];
    for (const view of views) {
      const query = viewQuery(new URLSearchParams(mapQuery(view.query)));
      const base = clip(view.name) || "Imported view";
      let done = false;
      let final = false;
      for (const name of [base, `${clip(base, 60 - SUFFIX.length)}${SUFFIX}`]) {
        if (existing.some((v) => v.name.toLowerCase() === name.toLowerCase() && v.query === query)) { done = true; break; }
        try {
          existing.push(await request<SavedView>("POST", "/api/v1/saved-views", { page, name, query }));
          done = true;
          break;
        } catch (error) {
          const code = error instanceof ApiError ? error.code : undefined;
          final = code !== undefined && FINAL.has(code);
          if (code !== "view_name_taken") break;
        }
      }
      if (done) continue;
      if (final) refused.push(base); else transient = true;
    }
  } catch {
    return; // unreachable or signed out: try again next time
  } finally {
    if (views.length > 0) invalidate(viewsPath(page));
  }
  if (refused.length > 0) toast(`These saved views couldn't be moved to your account: ${refused.join(", ")}`, true);
  if (transient) return;
  try { localStorage.removeItem(legacyKey); } catch { /* storage gone: nothing left to remove */ }
}

/**
 * Column changes in order: each PUT carries the full set after every toggle
 * so far, so quick toggles never undo each other. `shown` is that set while
 * saves are pending (undefined once the server's copy is current again).
 */
export function columnSaver(page: string, onChange: (pending: string[] | undefined) => void, onError: (error: unknown) => void,
  put: (page: string, hidden: string[]) => Promise<unknown> = setHiddenColumns) {
  let pending: string[] | undefined;
  let inFlight = 0;
  let chain: Promise<unknown> = Promise.resolve();
  return (server: readonly string[], key: string) => {
    const next = toggleHidden(pending ?? server, key);
    pending = next;
    inFlight += 1;
    onChange(next);
    // A failure keeps the queue's set, so a toggle made meanwhile builds on it;
    // the server's copy shows again once the queue has drained.
    chain = chain.then(() => put(page, next)).catch(onError)
      .finally(() => { inFlight -= 1; if (inFlight === 0) { pending = undefined; onChange(undefined); } });
  };
}
