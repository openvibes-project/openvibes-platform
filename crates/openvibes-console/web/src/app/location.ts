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

/** The old Vulnerabilities list's flags, in ruling 7's order: the first set wins as `signal`. */
const OLD_SIGNALS = [["exploited", "exploited"], ["reboot", "reboot"], ["nofix", "nofix"], ["lowconf", "lowconf"]] as const;
/** The old list's sorts that today's columns still have (it sorted in the browser). */
const OLD_VULN_SORTS = new Set(["severity", "cvss", "epss", "hosts", "due"]);

/** An old Vulnerabilities query as today's (roles 5b ruling 7): the flags
 * become one `signal`, and sorts no column has any more go with their direction. */
export function vulnerabilitiesQuery(query: string): string {
  const params = new URLSearchParams(query);
  const signal = OLD_SIGNALS.find(([flag]) => params.get(flag) === "true")?.[1];
  for (const [flag] of OLD_SIGNALS) params.delete(flag);
  if (signal) params.set("signal", signal);
  const sort = params.get("sort");
  if (sort !== null && !OLD_VULN_SORTS.has(sort)) { params.delete("sort"); params.delete("dir"); }
  return params.toString();
}

/** The Compliance list's sortable columns (roles 5c): the old list's other sorts are gone. */
const CHECK_SORTS = new Set(["severity", "check", "failing", "since"]);

/** An old Compliance query as today's (roles 5c ruling 9): `state=all` and
 * `severity` stay, the old window (`window`, `since`) goes, the rule-set chip
 * (`set`) is the Rule set filter, and sorts no column has any more go with their direction. */
export function complianceQuery(query: string): string {
  const params = new URLSearchParams(query);
  params.delete("window");
  params.delete("since");
  const set = params.get("set");
  params.delete("set");
  if (set && !params.has("rule_set")) params.set("rule_set", set);
  const sort = params.get("sort");
  if (sort !== null && !CHECK_SORTS.has(sort)) { params.delete("sort"); params.delete("dir"); }
  return params.toString();
}

/** A host's page (approved screen 17). */
export const hostPath = (id: string) => `/hosts/${encodeURIComponent(id)}`;

/** An alarm's page (approved screen 30). */
export const alarmPath = (id: string) => `/alarms/${encodeURIComponent(id)}`;

/** A vulnerability's page (approved screen 26): a CVE, or an advisory id the page resolves (roles 5b ruling 7). */
export const vulnPath = (key: string) => `/vulnerabilities/${encodeURIComponent(key)}`;

/** A check's page (approved screen 28): a rule of a rule set (roles 5c ruling 8); a finding from before rule sets
 * (stored with an empty set, as an agent export imports it) is `~unknown`, as the API spells it. */
export const checkPath = (ruleSet: string, rule: string) => `/compliance/${encodeURIComponent(ruleSet || "~unknown")}/${encodeURIComponent(rule)}`;

/** A finding ref's rule set and rule (`set/rule`, split at the first slash). */
export function splitFindingId(id: string): [string, string] {
  const split = id.indexOf("/");
  return split < 0 ? ["", id] : [id.slice(0, split), id.slice(split + 1)];
}

/** The check a finding ref (`set/rule`, or `/rule` from before rule sets) names. */
const findingPath = (id: string) => checkPath(...splitFindingId(id));

const PAGES: Record<string, (id: string) => string> = { agent: hostPath, alarm: alarmPath, advisory: vulnPath, finding: findingPath };

/** The page an object opens instead of a panel: a host, an alarm, an advisory or a check (a finding); null for a panel. */
export function pagePath(panel: PanelRef): string | null {
  return PAGES[panel.kind]?.(panel.id) ?? null;
}

/**
 * Old addresses as today's (plan ruling 1; roles 5a): `/agents?…` is the
 * Hosts list, and a host, alarm, advisory or finding panel opened on any view
 * (`?open=agent:ID`, `?open=alarm:ID`, `?open=advisory:ID`,
 * `?open=finding:SET/RULE`, the assistant's `/agents?agent=ID`) is that
 * object's page, a whole page with no panels (as `nav.open` opens it). A host
 * panel wins over an alarm panel, an alarm over an advisory, an advisory over
 * a finding (roles 5c ruling 9). The old Vulnerabilities flags are today's signals (roles 5b ruling 7),
 * and the old Compliance filters today's (roles 5c ruling 9).
 */
export function redirect(location: AppLocation): AppLocation {
  const host = location.view === "/agents" ? location.params.get("agent") : null;
  const panel = location.panels.find((p) => p.kind === "agent") ?? (host ? { kind: "agent", id: host }
    : ["alarm", "advisory", "finding"].map((kind) => location.panels.find((p) => p.kind === kind)).find(Boolean));
  const page = panel && pagePath(panel);
  if (page) return { view: page, panels: [], params: new URLSearchParams() };
  if (location.view === "/vulnerabilities") return { ...location, params: new URLSearchParams(vulnerabilitiesQuery(location.params.toString())) };
  if (location.view === "/compliance") return { ...location, params: new URLSearchParams(complianceQuery(location.params.toString())) };
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
