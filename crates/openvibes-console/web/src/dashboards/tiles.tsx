import { Fragment } from "react";
import { useResource } from "../api/client";
import type { AgentSummary, FindingSummary, Permission, VulnerabilitySummary } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { ObjectLink, SeverityBadge } from "../ui/bits";
import { count } from "../ui/format";
import { Icon } from "../ui/Icon";
import { LineChart } from "../ui/LineChart";
import { useListRows } from "../views/rows";
import { ATTENTION_KINDS, useAttention } from "./attention";
import { int, list, parseListConfig, str } from "./config";
import { useHistory } from "./history";
import { METRICS, METRIC_KEYS, delta, partText, permitted, trendDays, type Metric } from "./metrics";
import type { WidgetProps } from "./widgets";

export { METRICS, METRIC_KEYS, type Metric } from "./metrics";

export function Unavailable() {
  return <div className="tile-empty"><Icon name="ban" size={18} /> Not available with your role</div>;
}

// A count's number is the last point of its history: the API's live "today" value.
function useCount(metric: string | null, days = 7) {
  const { data } = useHistory(metric, days);
  return data;
}

function Part({ kind, id }: { kind: string; id: string }) {
  const value = useCount(id)?.at(-1)?.value;
  const [path, params] = METRICS[id as Metric].view as [string, Record<string, string>]; // catalogue.test.ts: every part has a view
  return <button type="button" className="link-button" onClick={() => nav.view(path, params)}>{value === undefined ? "…" : partText(kind, value)}</button>;
}

export function NumberTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const metric = str(widget.config, "metric", "agents.active", METRIC_KEYS);
  const def = METRICS[metric];
  const allowed = permitted(metric, (p) => can(p as Permission));
  const trend = trendDays(widget.config.trend);
  // trend <= 7 reuses the 7-day history the number needs anyway.
  const history = useCount(allowed ? metric : null, Math.max(7, trend));
  const value = history?.at(-1)?.value;
  const points = trend > 0 ? history?.slice(-trend) ?? [] : [];
  const change = delta(points);
  // No vulnerability feed yet: a 0 would claim nothing was found.
  const vulns = useResource<VulnerabilitySummary>(allowed && metric.startsWith("vulns.") ? "/api/v1/vulnerabilities/summary" : null);
  if (!allowed) return <Unavailable />;
  const tone = value && ["compliance.open.critical", "all.open.critical", "vulns.exploited"].includes(metric) ? "crit" : value && metric === "agents.stale" ? "warn" : undefined;
  const unset = vulns.data !== undefined && !vulns.data.feed_last_imported_at;
  // A vulnerability count waits for the summary, so no number turns into a dash.
  if (vulns.error) return <div className="tile-empty"><Icon name="alert" size={18} /> {vulns.error.message}</div>;
  const shown = metric.startsWith("vulns.") && vulns.data === undefined ? undefined : value;
  const body = (
    <>
      <span className={`stat__value num${tone && !unset ? ` stat__value--${tone}` : ""}`}>{unset ? <span aria-hidden="true">—</span> : shown === undefined ? "…" : count(shown)}</span>
      {unset && <span className="subtle">Not set up</span>}
      {!unset && change && <span className="delta">{change}</span>}
    </>
  );
  const view = def.view;
  const chart = trend > 0 && !unset && history && <LineChart series={[{ label: def.label, points }]} variant="spark" smooth={widget.config.line !== "stepped"} />;
  const parts = def.parts && <div className="tile-parts">{def.parts.map(([kind, id], i) => <Fragment key={id}>{i > 0 && " · "}<Part kind={kind} id={id} /></Fragment>)}</div>;
  return (
    <div className="stack">
      {view ? <button type="button" className="tile-number" onClick={() => nav.view(view[0], view[1])}>{body}</button>
        : <div className="tile-number tile-number--plain">{body}</div>}
      {chart}
      {parts}
    </div>
  );
}

export function BreakdownTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const source = str(widget.config, "source", "compliance", ["compliance", "vulnerabilities", "agents"] as const);
  const permission = source === "compliance" ? "compliance.read" : source === "agents" ? "agents.read" : "vulnerabilities.read";
  const allowed = can(permission);
  const findings = useResource<FindingSummary>(allowed && source === "compliance" ? "/api/v1/compliance/summary" : null);
  const vulns = useResource<VulnerabilitySummary>(allowed && source === "vulnerabilities" ? "/api/v1/vulnerabilities/summary" : null);
  const agents = useResource<AgentSummary>(allowed && source === "agents" ? "/api/v1/agents/summary" : null);
  if (!allowed) return <Unavailable />;
  if (vulns.data && !vulns.data.feed_last_imported_at) return <div className="tile-empty"><Icon name="alert" size={18} /> Vulnerability scanning is not set up</div>;
  const parts: { key: string; label: string; value: number; tone: string; go: () => void }[] =
    source === "compliance" ? (["critical", "high", "medium", "low"] as const).map((s) => ({ key: s, label: s, value: findings.data?.[s] ?? 0, tone: s, go: () => nav.view("/compliance", { severity: s }) }))
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
  const summary = useResource<VulnerabilitySummary>(can("vulnerabilities.read") ? "/api/v1/vulnerabilities/summary" : null);
  if (!can("vulnerabilities.read")) return <Unavailable />;
  if (summary.error) return <div className="tile-empty"><Icon name="alert" size={18} /> {summary.error.message}</div>;
  if (!summary.data) return <div className="skeleton" />;
  // No feed ever imported: zero hosts would claim a scan that never ran.
  if (!summary.data.feed_last_imported_at) return <div className="tile-empty"><Icon name="alert" size={18} /> Vulnerability scanning is not set up</div>;
  if (summary.data.top_hosts.length === 0) return <div className="tile-empty"><Icon name="check" size={18} /> No host has an open vulnerability</div>;
  return (
    <ul className="list list--plain">
      {summary.data.top_hosts.slice(0, int(widget.config, "limit", 6, 1, 10)).map((host) => (
        <li key={host.agent_id}><ObjectLink to={{ kind: "agent", id: host.agent_id }} className="list__row">
          <Icon name="agents" size={15} className="subtle" /><span className="grow truncate">{host.hostname ?? host.agent_id}</span>
          {host.serious > 0 && <span className="badge badge--high badge--plain num">{host.serious} serious</span>}<span className="subtle num nowrap">{host.open} open</span>
        </ObjectLink></li>
      ))}
    </ul>
  );
}
