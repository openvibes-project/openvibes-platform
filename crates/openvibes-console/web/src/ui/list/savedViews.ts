// Saved views and hidden columns, kept per person and page by the console
// (/api/v1/saved-views, /api/v1/list-columns/{page}).
import { ApiError, invalidate, prime, request, useResource } from "../../api/client";
import type { ListColumns, SavedView, SavedViewList } from "../../api/types";

const viewsPath = (page: string) => `/api/v1/saved-views?page=${encodeURIComponent(page)}`;
const columnsPath = (page: string) => `/api/v1/list-columns/${encodeURIComponent(page)}`;

/** The person's views on `page`, by name. */
export function useSavedViews(page: string): SavedView[] {
  return useResource<SavedViewList>(viewsPath(page)).data?.items ?? [];
}

/** The column keys the person hides on `page` (none until loaded). */
export function useHiddenColumns(page: string): string[] {
  return useResource<ListColumns>(columnsPath(page)).data?.hidden ?? [];
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

/**
 * Moves the views a page kept in this browser (before saved views lived on
 * the console) to the console, once: `mapQuery` turns an old query into
 * today's. Views the console refuses (a taken name, too many, invalid) are
 * dropped; on any other failure (unreachable, signed out) the key stays, to try again next time.
 */
export async function importBrowserViews(page: string, legacyKey: string, mapQuery: (query: string) => string): Promise<void> {
  let old: unknown;
  try {
    const raw = localStorage.getItem(legacyKey);
    if (raw === null) return;
    old = JSON.parse(raw);
  } catch {
    old = undefined; // no storage, or not JSON: nothing to import
  }
  const views = Array.isArray(old) ? old.filter((v): v is { name: string; query: string } => typeof v?.name === "string" && typeof v?.query === "string") : [];
  for (const view of views) {
    try {
      await request("POST", "/api/v1/saved-views", { page, name: view.name, query: mapQuery(view.query) });
    } catch (error) {
      if (!(error instanceof ApiError && (error.status === 409 || error.status === 422))) return;
    }
  }
  if (views.length > 0) invalidate(viewsPath(page));
  try { localStorage.removeItem(legacyKey); } catch { /* storage gone: nothing left to remove */ }
}
