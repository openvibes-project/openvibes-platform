import { useResource } from "../api/client";
import type { AgentSummary, FindingSummary, VulnerabilitySummary } from "../api/types";
import { nav } from "../app/nav";
import { useSession } from "../app/session";
import { ObjectLink, SeverityBadge } from "../ui/bits";
import { count } from "../ui/format";
import { Icon } from "../ui/Icon";
import { useListRows } from "../views/rows";
import { useAttention } from "./attention";
import { int, list, parseListConfig, str } from "./config";
import type { WidgetProps } from "./widgets";

export const METRICS = {
  "agents.active": { label: "Hosts online", permission: "agents.read", view: ["/agents", { status: "active" }] },
  "agents.stale": { label: "Stale hosts", permission: "agents.read", view: ["/agents", { status: "stale" }] },
  "agents.revoked": { label: "Revoked hosts", permission: "agents.read", view: ["/agents", { status: "revoked" }] },
  "findings.open.critical": { label: "Open critical findings", permission: "findings.read", view: ["/findings", { severity: "critical" }] },
  "findings.open.high": { label: "Open high findings", permission: "findings.read", view: ["/findings", { severity: "high" }] },
  "findings.open.medium": { label: "Open medium findings", permission: "findings.read", view: ["/findings", { severity: "medium" }] },
  "findings.open.low": { label: "Open low findings", permission: "findings.read", view: ["/findings", { severity: "low" }] },
  "vulns.exploited": { label: "Exploited", permission: "vulnerabilities.read", view: ["/vulnerabilities", { exploited: "true" }] },
  "vulns.reboot_hosts": { label: "Hosts needing a reboot", permission: "vulnerabilities.read", view: ["/vulnerabilities", { reboot: "true" }] },
  "vulns.no_fix": { label: "No fix yet", permission: "vulnerabilities.read", view: ["/vulnerabilities", { nofix: "true" }] },
} as const;
export type Metric = keyof typeof METRICS;
export const METRIC_KEYS = Object.keys(METRICS) as Metric[];

export function Unavailable() {
  return <div className="tile-empty"><Icon name="ban" size={18} /> Not available with your role</div>;
}

export function NumberTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const metric = str(widget.config, "metric", "agents.active", METRIC_KEYS);
  const def = METRICS[metric];
  const allowed = can(def.permission);
  const agents = useResource<AgentSummary>(allowed && metric.startsWith("agents.") ? "/api/v1/agents/summary" : null);
  const findings = useResource<FindingSummary>(allowed && metric.startsWith("findings.") ? "/api/v1/findings/summary" : null);
  const vulns = useResource<VulnerabilitySummary>(allowed && metric.startsWith("vulns.") ? "/api/v1/vulnerabilities/summary" : null);
  if (!allowed) return <Unavailable />;
  const value = metric === "agents.active" ? agents.data?.active : metric === "agents.stale" ? agents.data?.stale : metric === "agents.revoked" ? agents.data?.revoked
    : metric.startsWith("findings.open.") ? findings.data?.[metric.slice(14) as "critical" | "high" | "medium" | "low"]
      : metric === "vulns.exploited" ? vulns.data?.exploited : metric === "vulns.reboot_hosts" ? vulns.data?.reboot_hosts : vulns.data?.no_fix;
  const tone = value && (metric === "findings.open.critical" || metric === "vulns.exploited") ? "crit" : value && metric === "agents.stale" ? "warn" : undefined;
  // No vulnerability feed yet: a 0 would claim nothing was found.
  const unset = vulns.data !== undefined && !vulns.data.feed_last_imported_at;
  return (
    <button type="button" className="tile-number" onClick={() => nav.view(def.view[0], def.view[1])}>
      <span className={`stat__value num${tone && !unset ? ` stat__value--${tone}` : ""}`}>{unset ? <span aria-hidden="true">—</span> : value === undefined ? "…" : count(value)}</span>
      {unset && <span className="subtle">Not set up</span>}
    </button>
  );
}

export function BreakdownTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const source = str(widget.config, "source", "findings", ["findings", "vulnerabilities", "agents"] as const);
  const permission = source === "findings" ? "findings.read" : source === "agents" ? "agents.read" : "vulnerabilities.read";
  const allowed = can(permission);
  const findings = useResource<FindingSummary>(allowed && source === "findings" ? "/api/v1/findings/summary" : null);
  const vulns = useResource<VulnerabilitySummary>(allowed && source === "vulnerabilities" ? "/api/v1/vulnerabilities/summary" : null);
  const agents = useResource<AgentSummary>(allowed && source === "agents" ? "/api/v1/agents/summary" : null);
  if (!allowed) return <Unavailable />;
  if (vulns.data && !vulns.data.feed_last_imported_at) return <div className="tile-empty"><Icon name="alert" size={18} /> Vulnerability scanning is not set up</div>;
  const parts: { key: string; label: string; value: number; tone: string; go: () => void }[] =
    source === "findings" ? (["critical", "high", "medium", "low"] as const).map((s) => ({ key: s, label: s, value: findings.data?.[s] ?? 0, tone: s, go: () => nav.view("/findings", { severity: s }) }))
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
  const include = list(widget.config, "include", ["exploited", "findings", "stale"] as const);
  const { items, loading } = useAttention(include.length ? include : ["exploited", "findings", "stale"], int(widget.config, "limit", 8, 1, 20));
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
  const permission = { "/findings": "findings.read", "/vulnerabilities": "vulnerabilities.read", "/agents": "agents.read", "/audit": "audit.read" }[view] as "findings.read";
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
          {host.serious > 0 && <span className="badge badge--high badge--plain num">{host.serious} serious</span>}<span className="subtle num">{host.open}</span>
        </ObjectLink></li>
      ))}
    </ul>
  );
}
