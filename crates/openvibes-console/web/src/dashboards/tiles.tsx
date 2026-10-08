import { Fragment } from "react";
import { useResource } from "../api/client";
import type { AgentSummary, FindingSummary, Permission, TopHosts, VulnerabilitySummary } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { ObjectLink, SeverityBadge } from "../ui/bits";
import { count } from "../ui/format";
import { Icon } from "../ui/Icon";
import { CountError, Unavailable } from "./CountError";
import { LineChart } from "../ui/LineChart";
import { useListRows } from "../views/rows";
import { ATTENTION_KINDS, useAttention } from "./attention";
import { int, list, parseListConfig, str } from "./config";
import { useHistory } from "./history";
import { METRICS, METRIC_KEYS, delta, deltaSince, partText, scanNotSetUp, permitted, trendDays, type Metric } from "./metrics";
import type { WidgetProps } from "./widgets";

export { METRICS, METRIC_KEYS, type Metric } from "./metrics";

export { Unavailable };

// A count's number is the last point of its history: the API's live "today" value.
function useCount(metric: string | null, days = 7) {
  const { data, error } = useHistory(metric, days);
  return { data, error };
}

function Part({ kind, id, unset }: { kind: string; id: string; unset: boolean }) {
  const { data, error } = useCount(id);
  const value = data?.at(-1)?.value;
  // No vulnerability feed yet: a 0 would claim nothing was found.
  if (kind === "vulnerability" && unset) return <span>vulnerabilities not set up</span>;
  const [path, params] = METRICS[id as Metric].view as [string, Record<string, string>]; // catalogue.test.ts: every part has a view
  return <button type="button" className="link-button" onClick={() => nav.view(path, params)}>{error ? "—" : value === undefined ? "…" : partText(kind, value)}</button>;
}

export function NumberTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const metric = str(widget.config, "metric", "agents.active", METRIC_KEYS);
  const def = METRICS[metric];
  const allowed = permitted(metric, (p) => can(p as Permission));
  const trend = trendDays(widget.config.trend);
  // trend <= 7 reuses the 7-day history the number needs anyway.
  const { data: history, error: historyError } = useCount(allowed ? metric : null, Math.max(7, trend));
  const value = history?.at(-1)?.value;
  const points = trend > 0 ? history?.slice(-trend) ?? [] : [];
  const change = delta(points);
  const since = deltaSince(points, trend);
  // No vulnerability feed yet: a 0 would claim nothing was found.
  const vulns = useResource<VulnerabilitySummary>(allowed && (metric.startsWith("vulns.") || def.parts) ? "/api/v1/vulnerabilities/summary" : null);
  if (!allowed) return <Unavailable />;
  const tone = value && ["compliance.open.critical", "all.open.critical", "vulns.exploited"].includes(metric) ? "crit" : value && metric === "agents.stale" ? "warn" : undefined;
  const noFeed = vulns.data !== undefined && !vulns.data.feed_last_imported_at;
  const unset = noFeed && metric.startsWith("vulns.");
  // A vulnerability count waits for the summary, so no number turns into a dash.
  if (historyError) return <CountError error={historyError} />;
  if (vulns.error) return <div className="tile-empty"><Icon name="alert" size={18} /> {vulns.error.message}</div>;
  const shown = metric.startsWith("vulns.") && vulns.data === undefined ? undefined : value;
  const body = (
    <>
      <span className={`stat__value num${tone && !unset ? ` stat__value--${tone}` : ""}`}>{unset ? <span aria-hidden="true">—</span> : shown === undefined ? "…" : count(shown)}</span>
      {unset && <span className="subtle">Not set up</span>}
      {!unset && change && <span className="delta" title={`since ${points[0]?.day}`}>{change}{since && ` ${since}`}</span>}
    </>
  );
  const view = def.view;
  // Reserve the chart's height while history loads so the fine print does not jump.
  const chart = trend > 0 && !unset && <div style={{ minHeight: 36 }}>{history && <LineChart series={[{ label: def.label, points }]} variant="spark" smooth={widget.config.line !== "stepped"} />}</div>;
  const parts = def.parts && <div className="tile-parts">{def.parts.map(([kind, id], i) => <Fragment key={id}>{i > 0 && <span className="tile-parts__sep" aria-hidden="true"> · </span>}<Part kind={kind} id={id} unset={noFeed} /></Fragment>)}</div>;
  return (
    <div className="stack">
      {view ? <button type="button" className="tile-number" onClick={() => nav.view(view[0], view[1])}>{body}</button>
        : <div className="tile-number tile-number--plain">{body}</div>}
      {chart}
      {parts}
    </div>
  );
}

export const BREAKDOWN_SOURCES = ["alarms", "vulnerabilities", "compliance", "agents"] as const;
export const BREAKDOWN_TITLES = { alarms: "Active alarms by severity", vulnerabilities: "Vulnerabilities by severity", compliance: "Compliance findings by severity", agents: "Hosts by status" };
const ALARM_SEVERITIES = ["critical", "high", "medium", "low"] as const;

export function BreakdownTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const source = str(widget.config, "source", "compliance", BREAKDOWN_SOURCES);
  const permission = { alarms: "alarms.read", compliance: "compliance.read", agents: "agents.read", vulnerabilities: "vulnerabilities.read" }[source] as Permission;
  const allowed = can(permission);
  // The tiles' own numbers: the history API's live value (last point) of each alarm severity and of all.
  const alarmHistory = [...ALARM_SEVERITIES.map((s) => `alarms.active.${s}`), "alarms.active"].map((id) => useHistory(allowed && source === "alarms" ? id : null, 7)); // eslint-disable-line react-hooks/rules-of-hooks
  const alarmCounts = alarmHistory.map((h) => h.data?.at(-1)?.value);
  const alarmError = alarmHistory.find((h) => h.error)?.error;
  const findings = useResource<FindingSummary>(allowed && source === "compliance" ? "/api/v1/compliance/summary" : null);
  const vulns = useResource<VulnerabilitySummary>(allowed && source === "vulnerabilities" ? "/api/v1/vulnerabilities/summary" : null);
  const agents = useResource<AgentSummary>(allowed && source === "agents" ? "/api/v1/agents/summary" : null);
  if (!allowed) return <Unavailable />;
  if (alarmError) return <div className="tile-empty"><Icon name="alert" size={18} /> {alarmError.message}</div>;
  if (vulns.data && !vulns.data.feed_last_imported_at) return <div className="tile-empty"><Icon name="alert" size={18} /> Vulnerability scanning is not set up</div>;
  const parts: { key: string; label: string; value: number; tone: string; go: () => void }[] =
    source === "alarms" ? [...ALARM_SEVERITIES.map((s, i) => ({ key: s, label: s, value: alarmCounts[i] ?? 0, tone: s, go: () => nav.view("/alarms", { severity: s }) })),
      // Info is what the Active alarms tile counts beyond the four severities.
      { key: "info", label: "info", value: Math.max(0, (alarmCounts[4] ?? 0) - alarmCounts.slice(0, 4).reduce<number>((n, v) => n + (v ?? 0), 0)), tone: "unrated", go: () => nav.view("/alarms", { severity: "info" }) }]
      : source === "compliance" ? (["critical", "high", "medium", "low"] as const).map((s) => ({ key: s, label: s, value: findings.data?.[s] ?? 0, tone: s, go: () => nav.view("/compliance", { severity: s }) }))
      : source === "vulnerabilities" ? (vulns.data?.by_severity ?? []).map((row) => ({ key: row.severity, label: row.severity, value: row.count, tone: row.severity, go: () => nav.view("/vulnerabilities", { severity: row.severity }) }))
        : (["active", "stale", "revoked", "imported"] as const).map((s) => ({ key: s, label: s, value: agents.data?.[s] ?? 0, tone: { active: "low", stale: "medium", revoked: "high", imported: "unrated" }[s], go: () => nav.view("/agents", { status: s }) }));
  return (
    <div className="stack">
      <div className="bar" role="img" aria-label={parts.map((p) => `${p.value} ${p.label}`).join(", ")}>
        {parts.map((p) => p.value > 0 && <span key={p.key} className={p.tone} style={{ flexGrow: p.value }} />)}
      </div>
      <div className="legend">
        {parts.map((p) => <button key={p.key} type="button" className="legend__item" onClick={p.go}><span className={`legend__dot ${p.tone}`} />{p.label}<span className="num">{count(p.value)}</span></button>)}
      </div>
    </div>
  );
}

export function AttentionTile({ widget }: WidgetProps) {
  const include = list(widget.config, "include", ATTENTION_KINDS);
  const { items, loading } = useAttention(include.length ? include : ATTENTION_KINDS, int(widget.config, "limit", 8, 1, 20));
  if (loading && items.length === 0) return <div className="skeleton" />;
  if (items.length === 0) return <div className="tile-empty"><Icon name="check" size={18} /> All clear</div>;
  return (
    <ul className="attention__list">
      {items.map((item) => (
        <li key={item.key}>
          <ObjectLink to={item.to} fromList className="attention__row">
            <span className={`attention__icon attention__icon--${item.severity}`}><Icon name={item.icon} size={16} /></span>
            <span className="grow"><span className="attention__title truncate">{item.title}</span><span className="attention__meta">{item.meta}</span></span>
            {item.severity === "stale" ? <span className="badge badge--warn">Stale</span> : <SeverityBadge severity={item.severity} />}
          </ObjectLink>
        </li>
      ))}
    </ul>
  );
}

export function ListTile({ widget }: WidgetProps) {
  const parsed = parseListConfig(widget.config);
  if (!parsed) return <div className="tile-empty"><Icon name="alert" size={18} /> This list is not available</div>;
  return <ListTileBody view={parsed.view} params={parsed.params} limit={parsed.limit} />;
}

function ListTileBody({ view, params, limit }: NonNullable<ReturnType<typeof parseListConfig>>) {
  const { can } = useSession();
  const permission = { "/compliance": "compliance.read", "/vulnerabilities": "vulnerabilities.read", "/agents": "agents.read", "/audit": "audit.read" }[view] as "compliance.read";
  // Nothing is requested for a list the viewer's role cannot read.
  const allowed = can(permission, view === "/audit");
  const { rows, total, loading, error } = useListRows(allowed ? view : null, params);
  if (!allowed) return <Unavailable />;
  if (error) return <div className="tile-empty"><Icon name="alert" size={18} /> {error.message}</div>;
  if (loading) return <div className="skeleton" />;
  return (
    <div className="tile-list">
      {rows.length === 0 ? <div className="tile-empty"><Icon name="check" size={18} /> Nothing matches</div> : (
        <ul className="list list--plain">
          {rows.slice(0, limit).map((row) => (
            <li key={row.key}><ObjectLink to={row.open} className="list__row">
              <span className={`badge badge--${row.badge.tone}`}>{row.badge.label}</span>
              <span className="grow truncate">{row.title}</span><span className="subtle nowrap">{row.meta}</span>
            </ObjectLink></li>
          ))}
        </ul>
      )}
      <button type="button" className="link-button tile-more" onClick={() => nav.view(view, Object.fromEntries(params))}>Open list ({count(total)})</button>
    </div>
  );
}

export function TopHostsTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const all = widget.config.kinds !== "vulnerabilities";
  const limit = int(widget.config, "limit", 6, 1, 10);
  const allowedAll = can("alarms.read") && can("vulnerabilities.read") && can("compliance.read");
  const ranking = useResource<TopHosts>(all && allowedAll ? `/api/v1/metrics/top-hosts?limit=${limit}` : null);
  const summary = useResource<VulnerabilitySummary>(!all && can("vulnerabilities.read") ? "/api/v1/vulnerabilities/summary" : null);
  const unavailable = (text: string) => <div className="tile-empty"><Icon name="ban" size={18} /> {text}</div>;
  if (all ? !allowedAll : !can("vulnerabilities.read")) return all ? unavailable("Not available with your role — choose Vulnerabilities only") : <Unavailable />;
  const failed = all ? ranking.error : summary.error;
  // 403: the three kinds are readable with different scopes.
  if (all && ranking.error?.status === 403) return unavailable("Not available with your role — choose Vulnerabilities only");
  if (failed) return <div className="tile-empty"><Icon name="alert" size={18} /> {failed.message}</div>;
  // No feed ever imported: zero hosts would claim a scan that never ran.
  if (scanNotSetUp(all, summary.data)) return <div className="tile-empty"><Icon name="alert" size={18} /> Vulnerability scanning is not set up</div>;
  const hosts = all ? ranking.data?.items : summary.data?.top_hosts.slice(0, limit);
  if (!hosts) return <div className="skeleton" />;
  if (hosts.length === 0) return <div className="tile-empty"><Icon name="check" size={18} /> {all ? "No host has an open problem" : "No host has an open vulnerability"}</div>;
  return (
    <div className="stack">
      <ul className="list list--plain">
        {hosts.map((host) => (
          <li key={host.agent_id}><ObjectLink to={{ kind: "agent", id: host.agent_id }} className="list__row">
            <Icon name="agents" size={15} className="subtle" /><span className="grow truncate">{host.hostname ?? host.agent_id}</span>
            {host.serious > 0 && <span className="badge badge--high badge--plain num">{host.serious} serious</span>}<span className="subtle num nowrap">{host.serious > 0 && "· "}{host.open} open</span>
          </ObjectLink></li>
        ))}
      </ul>
      {all && <div className="subtle">all kinds; unrated vulnerabilities not counted</div>}
    </div>
  );
}
