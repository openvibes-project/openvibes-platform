// The whole navigation state lives in the URL: the view (path), the
// inspector's panel stack (`open=kind:id`, repeated, bottom first) and the
// view's own filters (every other query parameter). Back/forward, reload
// and shared links therefore restore exactly what was on screen.

export type PanelRef = { kind: string; id: string };

export type AppLocation = {
  view: string;
  panels: readonly PanelRef[];
  params: URLSearchParams;
};

export function parseLocation(pathname: string, search: string, base: string): AppLocation {
  const root = base.endsWith("/") ? base.slice(0, -1) : base;
  let view = pathname.startsWith(root) ? pathname.slice(root.length) : pathname;
  if (view === "" || view === "/index.html") view = "/";
  // Links from before the compliance rename (2026-10) keep working.
  if (view === "/findings") view = "/compliance";
  const params = new URLSearchParams(search);
  const panels = params.getAll("open").flatMap((value) => {
    const split = value.indexOf(":");
    if (split <= 0 || split === value.length - 1) return [];
    return [{ kind: value.slice(0, split), id: value.slice(split + 1) }];
  });
  params.delete("open");
  return redirect({ view, panels, params });
}

/** An old Hosts query as today's: status active → online, stale → offline;
 * the sort by seen or version is now by heartbeat or agent, and the old
 * status and enrolled sorts are gone. */
export function hostsQuery(query: string): string {
  const params = new URLSearchParams(query);
  const status = { active: "online", stale: "offline" }[params.get("status") ?? ""];
  if (status) params.set("status", status);
  const sort = params.get("sort");
  if (sort === "seen" || sort === "version") params.set("sort", sort === "seen" ? "heartbeat" : "agent");
  else if (sort === "status" || sort === "enrolled") { params.delete("sort"); params.delete("dir"); }
  return params.toString();
}

/** A host's page (approved screen 17). */
export const hostPath = (id: string) => `/hosts/${encodeURIComponent(id)}`;

/**
 * Old addresses as today's (plan ruling 1): `/agents?…` is the Hosts list,
 * and a host panel opened on any view (`?open=agent:ID`, the assistant's
 * `/agents?agent=ID`) is that host's page; the other panels stay open.
 */
export function redirect(location: AppLocation): AppLocation {
  const host = location.panels.find((p) => p.kind === "agent")?.id ?? (location.view === "/agents" ? location.params.get("agent") : null);
  if (host) return { view: hostPath(host), panels: location.panels.filter((p) => p.kind !== "agent"), params: new URLSearchParams() };
  if (location.view !== "/agents") return location;
  return { ...location, view: "/hosts", params: new URLSearchParams(hostsQuery(location.params.toString())) };
}

export function formatLocation(location: AppLocation, base: string): string {
  const root = base.endsWith("/") ? base.slice(0, -1) : base;
  const params = new URLSearchParams(location.params);
  for (const panel of location.panels) params.append("open", `${panel.kind}:${panel.id}`);
  const query = params.toString();
  return `${root}${location.view}${query === "" ? "" : `?${query}`}`;
}

export function samePanel(a: PanelRef, b: PanelRef): boolean {
  return a.kind === b.kind && a.id === b.id;
}

/** Opens `panel` on top of the stack; `fromList` starts a new stack. */
export function pushPanel(location: AppLocation, panel: PanelRef, fromList = false): AppLocation {
  if (fromList) return { ...location, panels: [panel] };
  const existing = location.panels.findIndex((candidate) => samePanel(candidate, panel));
  const panels = existing >= 0 ? location.panels.slice(0, existing + 1) : [...location.panels, panel];
  return { ...location, panels };
}

export function popPanel(location: AppLocation, count = 1): AppLocation {
  return { ...location, panels: location.panels.slice(0, Math.max(0, location.panels.length - count)) };
}
