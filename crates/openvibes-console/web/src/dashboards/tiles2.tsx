import { type ReactElement, cloneElement, useMemo } from "react";

import { useAllPages } from "../api/client";
import { useSession } from "../app/session";
import { daysAgo } from "../ui/format";
import { Trend, dailyHosts } from "../ui/trend";
import { LIST_VIEWS } from "../views/rows";
import { ATTENTION_KINDS } from "./attention";
import { int, list, noteLines, noteParts, str, toInt } from "./config";
import { LineChart } from "../ui/LineChart";
import { useHistory } from "./history";
import type { Permission } from "../api/types";
import { GRAPH_MAX_LINES, TREND_DAYS, graphLabel, graphMetrics, permitted, trendDays } from "./metrics";
import type { Metric } from "./metrics";
import { BREAKDOWN_SOURCES, BREAKDOWN_TITLES, METRIC_KEYS, Unavailable } from "./tiles";
import type { SettingsProps, WidgetProps } from "./widgets";

export function TrendTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const finding = str(widget.config, "finding", "", undefined);
  const days = [7, 14, 30].includes(int(widget.config, "days", 14, 7, 30)) ? int(widget.config, "days", 14, 7, 30) : 14;
  const [set = "", rule = ""] = finding.split("/");
  const history = useAllPages<{ agent_id: string; observed_day: string }>(can("compliance.read") && set && rule
    ? `/api/v1/compliance/history?since=${encodeURIComponent(daysAgo(days - 1))}&rule_set_id=${encodeURIComponent(set)}&rule_id=${encodeURIComponent(rule)}` : null, 3000);
  const counts = useMemo(() => dailyHosts(history.data ?? [], days), [history.data, days]);
  if (!can("compliance.read")) return <Unavailable />;
  if (!set || !rule) return <div className="tile-empty">Choose a compliance rule in this tile's settings</div>;
  return <Trend counts={counts} label={`hosts reporting ${rule}`} />;
}

const GRAPH_DAYS = [7, 30, 90, 365] as const;
const MAX_LINES = GRAPH_MAX_LINES;
const graphDays = (config: Record<string, unknown>) => GRAPH_DAYS.find((d) => d === config.days) ?? 30;

export function GraphTile({ widget }: WidgetProps) {
  const { can } = useSession();
  const metrics = graphMetrics(widget.config);
  const days = graphDays(widget.config);
  const allowed = metrics.every((m) => permitted(m, (p) => can(p as Permission)));
  // Hooks cannot loop over a list: always four, unused ones idle.
  const h = [0, 1, 2, 3].map((i) => useHistory(allowed && metrics[i] ? metrics[i] : null, days)); // eslint-disable-line react-hooks/rules-of-hooks
  if (!allowed) return <Unavailable />;
  const failed = h.find((r) => r.error);
  if (failed?.error) return <div className="tile-empty">{failed.error.message}</div>;
  if (metrics.some((_, i) => !h[i]?.data)) return <div className="skeleton" />;
  const series = metrics.map((m, i) => ({ label: graphLabel(m), points: h[i]?.data ?? [] }));
  return <LineChart series={series} variant="full" smooth={widget.config.line !== "stepped"} />;
}

export function GraphSettings({ widget, onChange }: SettingsProps) {
  const metrics = graphMetrics(widget.config);
  const set = (next: string[]) => onChange({ ...widget.config, metrics: next });
  return (
    <div className="stack">
      {metrics.map((m, i) => (
        <div key={i} className="row">
          {field(`Count ${i + 1}`, <select className="select" value={m} onChange={(e) => metrics.includes(e.target.value as Metric) || set(metrics.map((x, j) => j === i ? e.target.value : x))}>
            {METRIC_KEYS.map((key) => <option key={key} value={key} disabled={key !== m && metrics.includes(key)}>{graphLabel(key)}</option>)}
          </select>)}
          {metrics.length > 1 && <button type="button" className="button" aria-label={`Remove count ${i + 1}`} onClick={() => set(metrics.filter((_, j) => j !== i))}>Remove</button>}
        </div>
      ))}
      {metrics.length < MAX_LINES && <button type="button" className="button" onClick={() => set([...metrics, METRIC_KEYS.find((k) => !metrics.includes(k) && !k.startsWith("all.")) ?? "alarms.active"])}>+ Add count</button>}
      {field("Period", <select className="select" value={graphDays(widget.config)} onChange={(e) => onChange({ ...widget.config, days: Number(e.target.value) })}>
        {GRAPH_DAYS.map((d) => <option key={d} value={d}>{d} days</option>)}
      </select>)}
      {field("Line", <select className="select" value={widget.config.line === "stepped" ? "stepped" : "smooth"} onChange={(e) => onChange({ ...widget.config, line: e.target.value })}>
        <option value="smooth">Smooth</option><option value="stepped">Stepped</option>
      </select>)}
    </div>
  );
}

export function NoteTile({ widget }: WidgetProps) {
  const lines = Array.isArray(widget.config.text) ? (widget.config.text as unknown[]).filter((line): line is string => typeof line === "string").slice(0, 16) : [];
  return (
    <div className="tile-note">
      {lines.map((line, index) => (
        <p key={index}>{noteParts(line).map((part, i) => "href" in part
          ? <a key={i} href={part.href} target="_blank" rel="noreferrer noopener">{part.href}</a>
          : <span key={i}>{part.text}</span>)}</p>
      ))}
    </div>
  );
}

// The label text names the control exactly (a wrapping label alone would
// also read out a select's option texts).
const field = (label: string, control: ReactElement<{ "aria-label"?: string }>) =>
  <label className="field">{label}{cloneElement(control, { "aria-label": label })}</label>;

export function NumberSettings({ widget, onChange }: SettingsProps) {
  const metric = str(widget.config, "metric", "agents.active", METRIC_KEYS);
  const trend = trendDays(widget.config.trend);
  return (
    <div className="stack">
      {field("Count", <select className="select" value={metric} onChange={(e) => onChange({ ...widget.config, metric: e.target.value })}>
        {METRIC_KEYS.map((key) => <option key={key} value={key}>{graphLabel(key)}</option>)}
      </select>)}
      {field("Trend", <select className="select" value={trend} onChange={(e) => onChange({ ...widget.config, trend: Number(e.target.value) })}>
        {TREND_DAYS.map((d) => <option key={d} value={d}>{d === 0 ? "Off" : `${d} days`}</option>)}
      </select>)}
      {trend > 0 && field("Line", <select className="select" value={widget.config.line === "stepped" ? "stepped" : "smooth"} onChange={(e) => onChange({ ...widget.config, line: e.target.value })}>
        <option value="smooth">Smooth</option><option value="stepped">Stepped</option>
      </select>)}
    </div>
  );
}

export function BreakdownSettings({ widget, onChange }: SettingsProps) {
  return field("Break down", <select className="select" value={str(widget.config, "source", "compliance", BREAKDOWN_SOURCES)}
    onChange={(e) => onChange({ ...widget.config, source: e.target.value })}>
    {BREAKDOWN_SOURCES.map((source) => <option key={source} value={source}>{BREAKDOWN_TITLES[source]}</option>)}
  </select>);
}

export function AttentionSettings({ widget, onChange }: SettingsProps) {
  const include = list(widget.config, "include", ATTENTION_KINDS);
  const toggle = (value: string) => onChange({ ...widget.config, include: include.includes(value as never) ? include.filter((v) => v !== value) : [...include, value] });
  return (
    <div className="stack">
      {ATTENTION_KINDS.map((value) => (
        <label key={value} className="row"><input type="checkbox" checked={include.length === 0 || include.includes(value)} onChange={() => toggle(value)} />
          {{ alarms: "Active threat alarms (medium and above)", exploited: "Exploited vulnerabilities", serious: "Open critical and high vulnerabilities", compliance: "Open critical and high compliance findings", stale: "Hosts that stopped reporting" }[value]}</label>
      ))}
      {field("Show at most", <input className="input" type="number" min={1} max={20} value={int(widget.config, "limit", 8, 1, 20)} onChange={(e) => onChange({ ...widget.config, limit: toInt(e.target.value, 1, 20, 8) })} />)}
    </div>
  );
}

export function ListSettings({ widget, onChange }: SettingsProps) {
  return (
    <div className="stack">
      {field("List", <select className="select" value={str(widget.config, "view", "/compliance", LIST_VIEWS)} onChange={(e) => onChange({ ...widget.config, view: e.target.value })}>
        {LIST_VIEWS.map((v) => <option key={v} value={v}>{v.slice(1)}</option>)}
      </select>)}
      {field("Filters (as in the list's address, e.g. severity=critical)", <input className="input mono" value={str(widget.config, "query", "")} onChange={(e) => onChange({ ...widget.config, query: e.target.value })} />)}
      {field("Rows", <input className="input" type="number" min={1} max={20} step={1} value={int(widget.config, "limit", 8, 1, 20)} onChange={(e) => onChange({ ...widget.config, limit: toInt(e.target.value, 1, 20, 8) })} />)}
    </div>
  );
}

export function TrendSettings({ widget, onChange }: SettingsProps) {
  return (
    <div className="stack">
      {field("Compliance rule (rule set/rule, e.g. hardening-ssh/SSH-002)", <input className="input mono" value={str(widget.config, "finding", "")} onChange={(e) => onChange({ ...widget.config, finding: e.target.value })} />)}
      {field("Days", <select className="select" value={int(widget.config, "days", 14, 7, 30)} onChange={(e) => onChange({ ...widget.config, days: toInt(e.target.value, 7, 30, 14) })}>
        <option value={7}>7</option><option value={14}>14</option><option value={30}>30</option></select>)}
    </div>
  );
}

export function TopHostsSettings({ widget, onChange }: SettingsProps) {
  return (
    <div className="stack">
      {field("Count", <select className="select" value={widget.config.kinds === "vulnerabilities" ? "vulnerabilities" : "all"} onChange={(e) => onChange({ ...widget.config, kinds: e.target.value })}>
        <option value="all">All kinds (alarms, vulnerabilities, compliance)</option><option value="vulnerabilities">Vulnerabilities only</option>
      </select>)}
      {field("Hosts", <input className="input" type="number" min={1} max={10} value={int(widget.config, "limit", 6, 1, 10)} onChange={(e) => onChange({ ...widget.config, limit: toInt(e.target.value, 1, 10, 6) })} />)}
    </div>
  );
}

export function NoteSettings({ widget, onChange }: SettingsProps) {
  const text = Array.isArray(widget.config.text) ? (widget.config.text as string[]).join("\n") : "";
  return field("Text (plain; https:// links become clickable)", <textarea className="textarea" rows={6} maxLength={16 * 257} value={text}
    onChange={(e) => onChange({ ...widget.config, text: noteLines(e.target.value) })} />);
}
