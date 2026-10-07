// Navigation over the History API. Every change is a URL change, so the
// browser's back button closes panels and returns to earlier views.
import { useSyncExternalStore } from "react";

import { type AppLocation, type PanelRef, formatLocation, parseLocation, popPanel, pushPanel } from "./location";

const base = import.meta.env.BASE_URL;
const listeners = new Set<() => void>();
let snapshot: AppLocation = read();
let snapshotKey = window.location.pathname + window.location.search;
// An old /findings link: show the URL of the page it now opens.
if (window.location.pathname.endsWith("/findings")) {
  snapshotKey = formatLocation(snapshot, base);
  window.history.replaceState(null, "", snapshotKey);
}

function read(): AppLocation {
  return parseLocation(window.location.pathname, window.location.search, base);
}

function notify() {
  const key = window.location.pathname + window.location.search;
  if (key !== snapshotKey) {
    snapshotKey = key;
    snapshot = read();
  }
  for (const listener of listeners) listener();
}

let guard: (() => boolean) | null = null;

// Back and Forward consult the leave guard too; staying restores the URL.
window.addEventListener("popstate", () => {
  const next = read();
  if (guard && next.view !== snapshot.view && !guard()) {
    window.history.pushState(null, "", snapshotKey);
    return;
  }
  notify();
});

function go(next: AppLocation, replace = false) {
  const url = formatLocation(next, base);
  if (url === window.location.pathname + window.location.search) return;
  if (replace) window.history.replaceState(null, "", url);
  else window.history.pushState(null, "", url);
  notify();
}

export const nav = {
  /** A check `view()` consults first, e.g. "leave without saving?". */
  guard(check: (() => boolean) | null) { guard = check; },
  get location() { return snapshot; },
  href(view: string, params?: Record<string, string>) {
    return formatLocation({ view, panels: [], params: new URLSearchParams(params) }, base);
  },
  /** Switches view; open panels stay so switching does not lose context. */
  view(view: string, params?: Record<string, string>) {
    if (guard && !guard()) return;
    go({ view, panels: snapshot.panels, params: new URLSearchParams(params) });
  },
  open(panel: PanelRef, fromList = false) { go(pushPanel(snapshot, panel, fromList)); },
  back() { go(popPanel(snapshot)); },
  closeAll() { go({ ...snapshot, panels: [] }); },
  truncate(depth: number) { go({ ...snapshot, panels: snapshot.panels.slice(0, depth) }); },
  remove(panel: PanelRef) {
    go({ ...snapshot, panels: snapshot.panels.filter((p) => !(p.kind === panel.kind && p.id === panel.id)) });
  },
  /** Sets view parameters (filters, sort) without adding history entries. */
  setParams(changes: Record<string, string | null>) {
    const params = new URLSearchParams(snapshot.params);
    for (const [key, value] of Object.entries(changes)) {
      if (value === null || value === "") params.delete(key);
      else params.set(key, value);
    }
    go({ ...snapshot, params }, true);
  },
};

export function useLocation(): AppLocation {
  return useSyncExternalStore((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }, () => snapshot);
}
