// Ctrl+K: jump anywhere. Views, actions, recently opened objects, and a
// search across hosts, advisories/CVEs and findings in the viewer's scope.
import { useEffect, useMemo, useRef, useState } from "react";

import { useAllPages, useResource } from "../api/client";
import type { Agent, DashboardPage, FindingGroup, VulnerabilityPage } from "../api/types";
import { assistant } from "../app/assistant";
import type { PanelRef } from "../app/location";
import { nav } from "../app/nav";
import { objectTitle, panels, views } from "../app/registry";
import { useSession } from "../app/session";
import { windowsStore } from "../app/windows";
import { Icon, type IconName } from "../ui/Icon";
import { matches } from "../ui/table";
import { currentDensity, setDensity, setTheme } from "./theme";

type Item = { id: string; group: string; icon: IconName; label: string; hint?: string; run: () => void };

const recentKey = "openvibes.v2.recent";
export function rememberRecent(ref: PanelRef) {
  try {
    const list = (JSON.parse(localStorage.getItem(recentKey) ?? "[]") as PanelRef[]).filter((r) => !(r.kind === ref.kind && r.id === ref.id));
    localStorage.setItem(recentKey, JSON.stringify([ref, ...list].slice(0, 8)));
  } catch { /* convenience only */ }
}
function recent(): PanelRef[] {
  try { return (JSON.parse(localStorage.getItem(recentKey) ?? "[]") as PanelRef[]).filter((r) => typeof r?.kind === "string"); } catch { return []; }
}

export function CommandPalette({ onClose, canView }: { onClose: () => void; canView: (path: string) => boolean }) {
  const { can } = useSession();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const agents = useAllPages<Agent>(can("agents.read") ? "/api/v1/agents" : null);
  const vulns = useResource<VulnerabilityPage>(can("vulnerabilities.read") ? "/api/v1/vulnerabilities" : null);
  const dashboards = useResource<DashboardPage>("/api/v1/dashboards");
  const groups = useAllPages<FindingGroup>(can("findings.read") ? "/api/v1/findings/groups" : null);


  const items = useMemo(() => {
    const out: Item[] = [];
    const openObject = (ref: PanelRef) => () => nav.open(ref, true);
    const boards = [{ id: "overview", name: "Overview (built-in)", hint: "built-in" }, ...(dashboards.data?.items ?? []).map((d) => ({ id: d.dashboard_id, name: d.name, hint: d.mine ? "" : "shared" }))];
    for (const board of query.trim() === "" ? boards.slice(0, 5) : boards) {
      out.push({ id: `b${board.id}`, group: "Dashboards", icon: "overview", label: board.name, ...(board.hint ? { hint: board.hint } : {}), run: () => nav.view(`/dashboards/${board.id}`) });
    }
    for (const view of views) if (canView(view.path)) out.push({ id: `v${view.path}`, group: "Go to", icon: view.icon, label: view.label, hint: view.keys, run: () => nav.view(view.path) });
    if (can("assistant.use")) out.push({ id: "a-assistant", group: "Actions", icon: "sparkles", label: "Ask the assistant", hint: "Ctrl J", run: () => assistant.toggle() });
    if (can("tokens.create", true)) out.push({ id: "a-token", group: "Actions", icon: "enrollment", label: "New enrollment token", run: () => { nav.view("/enrollment"); nav.open({ kind: "enrollment-token", id: "new" }, true); } });
    out.push({ id: "a-dark", group: "Actions", icon: "moon", label: "Theme: dark", run: () => setTheme("dark") });
    out.push({ id: "a-light", group: "Actions", icon: "sun", label: "Theme: light", run: () => setTheme("light") });
    out.push({ id: "a-system", group: "Actions", icon: "monitor", label: "Theme: follow the system", run: () => setTheme("system") });
    out.push({ id: "a-windows", group: "Actions", icon: "layers", label: "Close all windows", run: () => windowsStore.closeAll() });
    out.push({ id: "a-density", group: "Actions", icon: "filter", label: "Toggle compact rows", run: () => setDensity(currentDensity() === "compact" ? "comfortable" : "compact") });
    if (query.trim() === "") {
      for (const ref of recent()) {
        const def = panels[ref.kind];
        if (def) out.push({ id: `r${ref.kind}:${ref.id}`, group: "Recent", icon: def.icon, label: objectTitle(ref), hint: def.label, run: openObject(ref) });
      }
      return out;
    }
    const filtered = out.filter((item) => matches([item.label, item.group], query));
    for (const agent of (agents.data ?? []).filter((a) => matches([a.hostname, a.id], query)).slice(0, 6)) {
      filtered.push({ id: `g${agent.id}`, group: "Hosts", icon: "agents", label: agent.hostname ?? agent.id, hint: agent.id, run: openObject({ kind: "agent", id: agent.id }) });
    }
    const seen = new Set<string>();
    for (const item of vulns.data?.items ?? []) {
      if (seen.has(item.advisory_id) || !matches([item.title, item.advisory_id, ...item.cves], query)) continue;
      seen.add(item.advisory_id);
      filtered.push({ id: `d${item.advisory_id}`, group: "Advisories", icon: "vulnerabilities", label: item.title, hint: item.advisory_id, run: openObject({ kind: "advisory", id: item.advisory_id }) });
      if (seen.size >= 6) break;
    }
    for (const group of (groups.data ?? []).filter((g) => matches([g.latest_message, g.rule_id, g.rule_set_id], query)).slice(0, 6)) {
      filtered.push({ id: `f${group.rule_set_id}/${group.rule_id}`, group: "Findings", icon: "findings", label: group.latest_message, hint: group.rule_id, run: openObject({ kind: "finding", id: `${group.rule_set_id}/${group.rule_id}` }) });
    }
    return filtered;
  }, [query, agents.data, vulns.data, groups.data, dashboards.data, can, canView]);

  useEffect(() => { list.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" }); }, [active]);

  const run = (item: Item | undefined) => { if (!item) return; onClose(); item.run(); };
  let lastGroup = "";
  return (
    <div className="palette-backdrop" onMouseDown={onClose}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Command palette" onMouseDown={(event) => event.stopPropagation()}
        onKeyDown={(event) => {
          if (event.key === "Escape") { event.preventDefault(); onClose(); }
          else if (event.key === "ArrowDown") { event.preventDefault(); setActive((a) => Math.min(items.length - 1, a + 1)); }
          else if (event.key === "ArrowUp") { event.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
          else if (event.key === "Enter") { event.preventDefault(); run(items[active]); }
        }}>
        <div className="palette__input">
          <Icon name="search" size={18} />
          <input ref={input} autoFocus value={query} onChange={(event) => { setQuery(event.target.value); setActive(0); }} placeholder="Search hosts, CVEs, findings, or type a command…"
            aria-label="Search" aria-controls="palette-results" aria-activedescendant={items[active] ? `pi-${active}` : undefined} role="combobox" aria-expanded="true" />
          <span className="kbd">Esc</span>
        </div>
        <ul className="palette__list" id="palette-results" role="listbox" ref={list}>
          {items.length === 0 && <li className="palette__empty">No results for “{query}”.</li>}
          {items.map((item, index) => {
            const header = item.group !== lastGroup ? item.group : null;
            lastGroup = item.group;
            return (
              <li key={item.id} role="presentation">
                {header && <div className="palette__group">{header}</div>}
                <div id={`pi-${index}`} role="option" aria-selected={index === active} data-index={index} className="palette__item"
                  onMouseMove={() => setActive(index)} onClick={() => run(item)}>
                  <Icon name={item.icon} size={16} />
                  <span className="grow truncate">{item.label}</span>
                  {item.hint && <span className="palette__hint">{item.hint}</span>}
                </div>
              </li>
            );
          })}
        </ul>
        <div className="palette__foot"><span><span className="kbd">↑</span><span className="kbd">↓</span> move</span><span><span className="kbd">↵</span> open</span><span><span className="kbd">?</span> shortcuts</span></div>
      </div>
    </div>
  );
}
