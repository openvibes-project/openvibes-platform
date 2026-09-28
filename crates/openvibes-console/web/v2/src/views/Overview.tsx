// "What needs me now": counts that link to filtered lists, and one attention
// list mixing exploited vulnerabilities, open serious findings and hosts
// that stopped reporting, each opening in the inspector.
import { useMemo } from "react";

import { useAllPages, useResource } from "../api/client";
import type { Agent, AgentSummary, FindingGroup, FindingSummary, VulnerabilityPage, VulnerabilitySummary } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { Ago, ObjectLink, SeverityBadge, Stat } from "../ui/bits";
import { count, plural } from "../ui/format";
import { Icon, type IconName } from "../ui/Icon";

export type AttentionItem = { key: string; icon: IconName; to: { kind: string; id: string }; severity: string; title: string; meta: string; rank: number };

export function greeting(now = new Date()) {
  const hour = now.getHours();
  return hour < 5 ? "Good night" : hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
}

/** The "Needs attention" list: exploited vulnerabilities, open critical and
 *  high findings, and hosts that stopped reporting, most urgent first. */
export function useAttention(include: readonly string[], limit: number): { items: AttentionItem[]; loading: boolean } {
  const { can } = useSession();
  const want = (kind: string) => include.includes(kind);
  const groups = useAllPages<FindingGroup>(want("findings") && can("findings.read") ? "/api/v1/findings/groups" : null);
  const exploited = useResource<VulnerabilityPage>(want("exploited") && can("vulnerabilities.read") ? "/api/v1/vulnerabilities?exploited=true" : null);
  const stale = useAllPages<Agent>(want("stale") && can("agents.read") ? "/api/v1/agents?state=stale" : null);

  const items = useMemo(() => {
    const items: AttentionItem[] = [];
    const byAdvisory = new Map<string, { title: string; severity: string; hosts: number }>();
    for (const item of exploited.data?.items ?? []) {
      const entry = byAdvisory.get(item.advisory_id) ?? { title: item.title, severity: item.severity, hosts: 0 };
      entry.hosts += 1;
      byAdvisory.set(item.advisory_id, entry);
    }
    for (const [id, entry] of byAdvisory) {
      items.push({ key: `a${id}`, icon: "flame", to: { kind: "advisory", id }, severity: entry.severity, title: entry.title, meta: `Known exploited · ${plural(entry.hosts, "host")}`, rank: 0 - entry.hosts / 1000 });
    }
    for (const group of groups.data ?? []) {
      if (group.triage_counts.open === 0 || (group.severity !== "critical" && group.severity !== "high")) continue;
      items.push({ key: `f${group.rule_set_id}/${group.rule_id}`, icon: "findings", to: { kind: "finding", id: `${group.rule_set_id}/${group.rule_id}` }, severity: group.severity, title: group.latest_message, meta: `${group.rule_id} · ${plural(group.triage_counts.open, "host")} open`, rank: (group.severity === "critical" ? 1 : 3) - group.triage_counts.open / 1000 });
    }
    const silent = [...(stale.data ?? [])].sort((a, b) => (a.last_seen_at ?? "").localeCompare(b.last_seen_at ?? "")).slice(0, 6);
    for (const agent of silent) {
      items.push({ key: `g${agent.id}`, icon: "agents", to: { kind: "agent", id: agent.id }, severity: "stale", title: agent.hostname ?? agent.id, meta: "Stopped reporting", rank: 2 });
    }
    return items.sort((a, b) => a.rank - b.rank);
  }, [exploited.data, groups.data, stale.data]);
  return { items: items.slice(0, limit), loading: groups.loading || exploited.loading || stale.loading };
}

export function Overview() {
  const { can, session } = useSession();
  const agents = useResource<AgentSummary>(can("agents.read") ? "/api/v1/agents/summary" : null);
  const findings = useResource<FindingSummary>(can("findings.read") ? "/api/v1/findings/summary" : null);
  const vulns = useResource<VulnerabilitySummary>(can("vulnerabilities.read") ? "/api/v1/vulnerabilities/summary" : null);
  const { items: attention, loading } = useAttention(["exploited", "findings", "stale"], 100);
  const stale = useAllPages<Agent>(can("agents.read") ? "/api/v1/agents?state=stale" : null);

  const name = session?.principal.display_name.split(" ")[0];
  const vulnTotal = vulns.data?.by_severity.reduce((sum, row) => sum + row.count, 0) ?? 0;

  return (
    <div className="view view--overview">
      <header className="overview-hero">
        <div>
          <h1>{greeting()}{name ? `, ${name}` : ""}</h1>
          <p className="muted">
            {agents.data ? <>{plural(agents.data.active, "host")} reporting{agents.data.stale > 0 && <>, <button type="button" className="link-button" onClick={() => nav.view("/agents", { status: "stale" })}>{agents.data.stale} stale</button></>}.</> : "Loading your fleet…"}
            {" "}{attention.length === 0 && !loading ? "Nothing needs your attention right now." : attention.length > 0 ? `${plural(attention.length, "thing")} to look at.` : ""}
          </p>
        </div>
      </header>

      <div className="stats">
        {agents.data && <Stat label="Hosts online" value={count(agents.data.active)} hint={`of ${count(agents.data.total)}`} onClick={() => nav.view("/agents", { status: "active" })} />}
        {agents.data && <Stat label="Stale" value={count(agents.data.stale)} tone={agents.data.stale > 0 ? "warn" : undefined} onClick={() => nav.view("/agents", { status: "stale" })} />}
        {findings.data && <Stat label="Open critical findings" value={count(findings.data.critical)} tone={findings.data.critical > 0 ? "crit" : undefined} onClick={() => nav.view("/findings", { severity: "critical" })} />}
        {findings.data && <Stat label="Open high findings" value={count(findings.data.high)} tone={findings.data.high > 0 ? "bad" : undefined} onClick={() => nav.view("/findings", { severity: "high" })} />}
        {vulns.data && <Stat label="Exploited" value={count(vulns.data.exploited)} tone={vulns.data.exploited > 0 ? "crit" : undefined} hint="host vulnerabilities" onClick={() => nav.view("/vulnerabilities", { exploited: "true" })} />}
        {vulns.data && <Stat label="Need a reboot" value={count(vulns.data.reboot_hosts)} hint="hosts" onClick={() => nav.view("/vulnerabilities", { reboot: "true" })} />}
      </div>

      <div className="overview-grid">
        <section className="card attention">
          <div className="card__head"><h2 className="card__title">Needs attention</h2><span className="subtle num">{attention.length || ""}</span></div>
          {loading && attention.length === 0 ? <div className="card__body"><div className="skeleton" /><div className="skeleton" style={{ marginTop: 10, width: "70%" }} /></div> : attention.length === 0 ? (
            <div className="empty"><Icon name="check" size={28} /><h3>All clear</h3><p>No exploited vulnerabilities, open serious findings or silent hosts.</p></div>
          ) : (
            <ul className="attention__list">
              {attention.slice(0, 14).map((item) => (
                <li key={item.key}>
                  <ObjectLink to={item.to} fromList className="attention__row">
                    <span className={`attention__icon attention__icon--${item.severity}`}><Icon name={item.icon} size={16} /></span>
                    <span className="grow">
                      <span className="attention__title truncate">{item.title}</span>
                      <span className="attention__meta">{item.meta}</span>
                    </span>
                    {item.severity === "stale" ? <span className="badge badge--warn">Stale</span> : <SeverityBadge severity={item.severity} />}
                    <Icon name="chevronRight" size={16} className="subtle" />
                  </ObjectLink>
                </li>
              ))}
            </ul>
          )}
        </section>

        <div className="stack">
          {findings.data && (
            <section className="card">
              <div className="card__head"><h2 className="card__title">Open findings</h2><button type="button" className="link-button" onClick={() => nav.view("/findings")}>All findings</button></div>
              <div className="card__body stack">
                <div className="bar" role="img" aria-label="Open findings by severity">
                  {(["critical", "high", "medium", "low"] as const).map((s) => findings.data && findings.data[s] > 0 && <span key={s} className={s} style={{ flexGrow: findings.data[s] }} />)}
                </div>
                <div className="legend">
                  {(["critical", "high", "medium", "low"] as const).map((s) => (
                    <button key={s} type="button" className="legend__item" onClick={() => nav.view("/findings", { severity: s })}>
                      <span className={`legend__dot ${s}`} />{s[0]?.toUpperCase()}{s.slice(1)}<span className="num">{findings.data?.[s]}</span>
                    </button>
                  ))}
                </div>
                <p className="subtle">{plural(findings.data.impacted_agents, "host")} affected.</p>
              </div>
            </section>
          )}
          {vulns.data && (
            <section className="card">
              <div className="card__head"><h2 className="card__title">Most exposed hosts</h2><span className="subtle">{plural(vulnTotal, "open vulnerability", "open vulnerabilities")}</span></div>
              <ul className="list">
                {vulns.data.top_hosts.slice(0, 6).map((host) => (
                  <li key={host.agent_id}>
                    <ObjectLink to={{ kind: "agent", id: host.agent_id }} fromList className="list__row">
                      <Icon name="agents" size={15} className="subtle" />
                      <span className="grow truncate">{host.hostname ?? host.agent_id}</span>
                      {host.serious > 0 && <span className="badge badge--high badge--plain num">{host.serious} serious</span>}
                      <span className="subtle num">{host.open}</span>
                    </ObjectLink>
                  </li>
                ))}
              </ul>
            </section>
          )}
          {stale.data && stale.data.length > 0 && (
            <p className="subtle overview-foot"><Icon name="clock" size={14} /><span>Oldest silent host: last report <Ago value={[...stale.data].sort((a, b) => (a.last_seen_at ?? "").localeCompare(b.last_seen_at ?? ""))[0]?.last_seen_at} /></span></p>
          )}
        </div>
      </div>
    </div>
  );
}
