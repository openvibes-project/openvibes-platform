import { useMemo } from "react";

import { useAllPages } from "../api/client";
import { useSession } from "../app/session";
import { daysAgo } from "../ui/format";
import { Trend, dailyHosts } from "../ui/trend";
import { int, noteParts, str } from "./config";
import { LineChart } from "../ui/LineChart";
import { useHistory } from "./history";
import type { Permission } from "../api/types";
import { graphLabel, graphMetrics, permitted } from "./metrics";
import { Unavailable } from "./tiles";
import type { WidgetProps } from "./widgets";

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

export const GRAPH_DAYS = [7, 30, 90, 365] as const;
export const graphDays = (config: Record<string, unknown>) => GRAPH_DAYS.find((d) => d === config.days) ?? 30;

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
