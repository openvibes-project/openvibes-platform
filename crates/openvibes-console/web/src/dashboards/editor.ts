// The dashboard being edited: one draft at a time, shared by the grid, the
// widget gallery and the settings panels. Only the owner may edit; saves
// carry the version so a second tab cannot overwrite silently.
import { useSyncExternalStore } from "react";

import { ApiError, invalidate, prime, request } from "../api/client";
import type { Dashboard } from "../api/types";
import { type FieldProblem, type Layout, type Widget, type WidgetType, addWidget, moveWidget, removeWidget, validateLayout, validateName } from "./layout";
import { WIDGET_DEFAULTS } from "./defaults";
import { upgradeLayout } from "./legacy";

export type EditorState = {
  dashboard: Dashboard | null; name: string; draft: Layout | null; dirty: boolean;
  saving: boolean; conflict: boolean; problems: FieldProblem[]; selected: string | null;
  /** The last removed tile, for Undo. */
  removed: Widget | null;
  /** Created by New and never saved: Cancel deletes it (#252). */
  fresh: boolean;
};

const empty: EditorState = { dashboard: null, name: "", draft: null, dirty: false, saving: false, conflict: false, problems: [], selected: null, removed: null, fresh: false };
let state = empty;
// The deletion of a cancelled, never-saved new dashboard, while one runs.
let discarding: Promise<void> = Promise.resolve();
const listeners = new Set<() => void>();
// Unsaved drafts are kept per tab, so a lost session, reload or crash does not
// lose them; leaving on purpose, Cancel and Save clear them.
const draftKey = (id: string) => `openvibes.v2.draft.${id}`;
type StoredDraft = { name: string; draft: Layout; at: string };
function storeDraft() {
  if (!state.dashboard || !state.draft || !state.dirty) return;
  try { sessionStorage.setItem(draftKey(state.dashboard.dashboard_id), JSON.stringify({ name: state.name, draft: state.draft, at: new Date().toISOString() })); } catch { /* recovery is a convenience */ }
}
function dropDraft(id: string | undefined) {
  if (!id) return;
  try { sessionStorage.removeItem(draftKey(id)); } catch { /* nothing stored */ }
}

const set = (next: Partial<EditorState>) => {
  state = { ...state, ...next };
  storeDraft();
  for (const listener of listeners) listener();
};
export const editorState = () => state;

function problemsOf(error: unknown): FieldProblem[] {
  if (error instanceof ApiError && error.fieldErrors?.length) return error.fieldErrors;
  return [{ field: "dashboard", code: "save_failed", message: error instanceof Error ? error.message : "Save failed" }];
}

export const editor = {
  state: () => state,
  begin(dashboard: Dashboard, opts: { fresh?: boolean } = {}): boolean {
    if (!dashboard.mine) return false;
    set({ ...empty, dashboard, name: dashboard.name, draft: upgradeLayout(dashboard.layout as unknown as Layout), fresh: opts.fresh === true });
    return true;
  },
  /** Ends editing and forgets the draft (the user chose to leave or cancel). A dashboard
   *  New made and that was never saved is deleted too (#252); settled() waits for that. */
  cancel() {
    const { dashboard, fresh } = state;
    dropDraft(dashboard?.dashboard_id);
    set(empty);
    if (!fresh || !dashboard) return;
    discarding = request("DELETE", `/api/v1/dashboards/${dashboard.dashboard_id}`).then(
      () => { invalidate("/api/v1/dashboards"); invalidate("/api/v1/me/home"); },
      () => { /* already gone or not allowed: nothing to clean up */ });
  },
  /** Resolves once a cancelled new dashboard's deletion has finished. */
  settled: () => discarding,
  /** Ends editing but keeps the stored draft (the page went away, e.g. the session ended). */
  suspend() { state = empty; for (const listener of listeners) listener(); },
  /** A stored draft for this dashboard, if one was left unsaved. */
  recoverable(id: string): StoredDraft | null {
    try {
      const parsed = JSON.parse(sessionStorage.getItem(draftKey(id)) ?? "null") as StoredDraft | null;
      if (!parsed || typeof parsed.name !== "string" || typeof parsed.draft !== "object" || !Array.isArray(parsed.draft?.widgets)) return null;
      return { ...parsed, draft: upgradeLayout(parsed.draft) };
    } catch {
      return null;
    }
  },
  recover(dashboard: Dashboard) {
    const stored = editor.recoverable(dashboard.dashboard_id);
    if (!stored || !editor.begin(dashboard)) return;
    set({ name: stored.name, draft: stored.draft, dirty: true });
  },
  rename(name: string) { set({ name, dirty: true }); },
  change(layout: Layout) { set({ draft: layout, dirty: true }); },
  add(type: WidgetType): string {
    const def = WIDGET_DEFAULTS[type];
    const { layout, id } = addWidget(state.draft ?? { schema: 1, widgets: [] }, type, def.size, def.config);
    set({ draft: layout, dirty: true, selected: id });
    return id;
  },
  configure(id: string, config: Widget["config"]) {
    if (!state.draft) return;
    set({ draft: { ...state.draft, widgets: state.draft.widgets.map((w) => (w.id === id ? { ...w, config } : w)) }, dirty: true });
  },
  remove(id: string) {
    if (!state.draft) return;
    const removed = state.draft.widgets.find((w) => w.id === id) ?? null;
    set({ draft: removeWidget(state.draft, id), dirty: true, selected: state.selected === id ? null : state.selected, removed });
  },
  undo() {
    if (!state.draft || !state.removed) return;
    const back = state.removed;
    set({ draft: moveWidget({ ...state.draft, widgets: [...state.draft.widgets, back] }, back.id, back.x, back.y), removed: null, selected: back.id });
  },
  select(id: string | null) { set({ selected: id }); },
  async save(): Promise<Dashboard | undefined> {
    const { dashboard, draft } = state;
    if (!dashboard || !draft) return undefined;
    const name = validateName(state.name);
    const problems = [...(typeof name === "string" ? [] : [name]), ...validateLayout(draft)];
    if (problems.length) { set({ problems }); return undefined; }
    set({ saving: true, problems: [] });
    try {
      const saved = await request<Dashboard>("PUT", `/api/v1/dashboards/${dashboard.dashboard_id}`, { name, layout: draft }, { "if-match": `"${dashboard.version}"` });
      invalidate("/api/v1/dashboards");
      // The saved dashboard is shown at once; no flash of the old layout.
      prime(`/api/v1/dashboards/${saved.dashboard_id}`, saved);
      dropDraft(saved.dashboard_id);
      set({ ...empty });
      return saved;
    } catch (error) {
      if (error instanceof ApiError && error.status === 412) set({ saving: false, conflict: true });
      else set({ saving: false, problems: problemsOf(error) });
      return undefined;
    }
  },
  async saveAsCopy(): Promise<Dashboard | undefined> {
    if (!state.draft) return undefined;
    set({ saving: true });
    try {
      const copy = await request<Dashboard>("POST", "/api/v1/dashboards", { name: state.name.trim() || "Untitled dashboard", layout: state.draft });
      invalidate("/api/v1/dashboards");
      dropDraft(state.dashboard?.dashboard_id);
      set({ ...empty });
      return copy;
    } catch (error) {
      set({ saving: false, problems: problemsOf(error) });
      return undefined;
    }
  },
  async reloadTheirs() {
    if (!state.dashboard) return;
    dropDraft(state.dashboard.dashboard_id);
    invalidate(`/api/v1/dashboards/${state.dashboard.dashboard_id}`);
    const fresh = await request<Dashboard>("GET", `/api/v1/dashboards/${state.dashboard.dashboard_id}`);
    editor.begin(fresh);
  },
};

export function useEditor(): EditorState {
  return useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, () => state);
}
