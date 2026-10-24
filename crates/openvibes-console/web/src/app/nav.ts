// Navigation over the History API. Every change is a URL change, so the
// browser's back button closes panels and returns to earlier views.
import { useSyncExternalStore } from "react";

import { type AppLocation, type PanelRef, formatLocation, pagePath, parseLocation, popPanel, pushPanel, redirect } from "./location";

const base = import.meta.env.BASE_URL;
const listeners = new Set<() => void>();
let snapshot: AppLocation = read();
let snapshotKey = window.location.pathname + window.location.search;
settle();

/** An old /findings, /agents, Vulnerabilities or Compliance address, or an old host, alarm or advisory panel: show the URL
 * of the page it now opens, in place, so history keeps no dead entry (plan ruling 1). */
function settle() {
  const oldVulns = /\/vulnerabilities$/.test(window.location.pathname) && /[?&](exploited|reboot|nofix|lowconf|sort)=/.test(window.location.search);
  const oldChecks = /\/compliance$/.test(window.location.pathname) && /[?&](window|since|set|sort)=/.test(window.location.search);
  if (!oldVulns && !oldChecks && !/\/(findings|agents)$/.test(window.location.pathname) && !/[?&]open=(agent|alarm|advisory)(%3A|:)/i.test(window.location.search)) return;
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
  settle();
});

function go(to: AppLocation, replace = false) {
  const next = redirect(to);
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
  /** A host, an alarm or an advisory is a whole page (approved screens 17, 30 and 26): opening one goes there and closes the panels. */
  open(panel: PanelRef, fromList = false) {
    const page = pagePath(panel);
    if (page === null) { go(pushPanel(snapshot, panel, fromList)); return; }
    if (guard && !guard()) return;
    go({ view: page, panels: [], params: new URLSearchParams() });
  },
  /** Goes to `view` in place of the current entry (a page whose address resolves to another). */
  replace(view: string, params?: Record<string, string>) {
    go({ view, panels: [], params: new URLSearchParams(params) }, true);
  },
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

type Click = { button: number; metaKey: boolean; ctrlKey: boolean; shiftKey: boolean; altKey: boolean; preventDefault(): void };

/** An in-console link's props: a plain left click navigates in place; with a
 * modifier key or another button the browser opens the href (new tab, window). */
export function viewLink(view: string, params?: Record<string, string>) {
  return {
    href: nav.href(view, params),
    onClick: (e: Click) => {
      if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      e.preventDefault();
      nav.view(view, params);
    },
  };
}

/** The panel on top of the stack: the one a list highlights as open. */
export function useTopPanel() {
  const { panels } = useLocation();
  return panels[panels.length - 1];
}

export function useLocation(): AppLocation {
  return useSyncExternalStore((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }, () => snapshot, () => snapshot);
}
