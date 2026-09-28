// The dashboard being edited: one draft at a time, shared by the grid, the
// widget gallery and the settings panels. Only the owner may edit; saves
// carry the version so a second tab cannot overwrite silently.
import { useSyncExternalStore } from "react";

import { ApiError, invalidate, request } from "../api/client";
import type { Dashboard } from "../api/types";
import { type FieldProblem, type Layout, type Widget, type WidgetType, addWidget, removeWidget, validateLayout, validateName } from "./layout";
import { WIDGET_DEFAULTS } from "./defaults";

export type EditorState = {
  dashboard: Dashboard | null; name: string; draft: Layout | null; dirty: boolean;
  saving: boolean; conflict: boolean; problems: FieldProblem[]; selected: string | null;
};

const empty: EditorState = { dashboard: null, name: "", draft: null, dirty: false, saving: false, conflict: false, problems: [], selected: null };
let state = empty;
const listeners = new Set<() => void>();
const set = (next: Partial<EditorState>) => { state = { ...state, ...next }; for (const listener of listeners) listener(); };
export const editorState = () => state;

function problemsOf(error: unknown): FieldProblem[] {
  if (error instanceof ApiError && error.fieldErrors?.length) return error.fieldErrors;
  return [{ field: "dashboard", code: "save_failed", message: error instanceof Error ? error.message : "Save failed" }];
}

export const editor = {
  state: () => state,
  begin(dashboard: Dashboard): boolean {
    if (!dashboard.mine) return false;
    set({ ...empty, dashboard, name: dashboard.name, draft: dashboard.layout as unknown as Layout });
    return true;
  },
  cancel() { set(empty); },
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
    set({ draft: removeWidget(state.draft, id), dirty: true, selected: state.selected === id ? null : state.selected });
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
      set({ ...empty });
      return copy;
    } catch (error) {
      set({ saving: false, problems: problemsOf(error) });
      return undefined;
    }
  },
  async reloadTheirs() {
    if (!state.dashboard) return;
    invalidate(`/api/v1/dashboards/${state.dashboard.dashboard_id}`);
    const fresh = await request<Dashboard>("GET", `/api/v1/dashboards/${state.dashboard.dashboard_id}`);
    editor.begin(fresh);
  },
};

export function useEditor(): EditorState {
  return useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, () => state);
}
