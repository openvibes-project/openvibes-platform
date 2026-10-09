// The widget types a dashboard can hold. Adding one: an entry here, its
// type in layout.ts's WIDGET_TYPES, and the same name in the server's
// allow-list (openvibes-console/src/dashboards.rs).
import type { ReactNode } from "react";

import type { IconName } from "../ui/Icon";
import { str } from "./config";
import { graphLabel, graphMetrics } from "./metrics";
import { WIDGET_DEFAULTS } from "./defaults";
import type { Widget, WidgetType } from "./layout";
import { AttentionTile, BREAKDOWN_SOURCES, BREAKDOWN_TITLES, BreakdownTile, ListTile, METRIC_KEYS, METRICS, NumberTile, TopHostsTile } from "./tiles";
import { GraphTile, NoteTile, TrendTile } from "./tiles2";
import { AttentionSettings, BreakdownSettings, GraphSettings, ListSettings, NoteSettings, NumberSettings, TopHostsSettings, TrendSettings } from "./settings";

export type WidgetProps = { widget: Widget };
export type SettingsProps = { widget: Widget; onChange: (config: Widget["config"]) => void };
export type WidgetDef = {
  type: WidgetType; label: string; description: string; icon: IconName; size: { w: number; h: number };
  defaults: Widget["config"]; View: (props: WidgetProps) => ReactNode; Settings: (props: SettingsProps) => ReactNode;
};

export const widgetDefs: Readonly<Record<WidgetType, WidgetDef>> = {
  number: { type: "number", label: "Number", description: "One count that opens its list", icon: "hash", size: WIDGET_DEFAULTS["number"].size, defaults: WIDGET_DEFAULTS["number"].config, View: NumberTile, Settings: NumberSettings },
  breakdown: { type: "breakdown", label: "Breakdown", description: "A severity or status bar", icon: "barStacked", size: WIDGET_DEFAULTS["breakdown"].size, defaults: WIDGET_DEFAULTS["breakdown"].config, View: BreakdownTile, Settings: BreakdownSettings },
  attention: { type: "attention", label: "Needs attention", description: "Exploited, serious and silent, in one list", icon: "alert", size: WIDGET_DEFAULTS["attention"].size, defaults: WIDGET_DEFAULTS["attention"].config, View: AttentionTile, Settings: AttentionSettings },
  list: { type: "list", label: "List", description: "The first rows of any list, with its filters", icon: "list", size: WIDGET_DEFAULTS["list"].size, defaults: WIDGET_DEFAULTS["list"].config, View: ListTile, Settings: ListSettings },
  trend: { type: "trend", label: "Trend", description: "Hosts reporting a compliance finding per day", icon: "chartBar", size: WIDGET_DEFAULTS["trend"].size, defaults: WIDGET_DEFAULTS["trend"].config, View: TrendTile, Settings: TrendSettings },
  "top-hosts": { type: "top-hosts", label: "Most exposed hosts", description: "Hosts with the most serious problems", icon: "agents", size: WIDGET_DEFAULTS["top-hosts"].size, defaults: WIDGET_DEFAULTS["top-hosts"].config, View: TopHostsTile, Settings: TopHostsSettings },
  graph: { type: "graph", label: "Graph", description: "Counts over time", icon: "chartLine", size: WIDGET_DEFAULTS["graph"].size, defaults: WIDGET_DEFAULTS["graph"].config, View: GraphTile, Settings: GraphSettings },
  note: { type: "note", label: "Note", description: "Plain text for your team", icon: "note", size: WIDGET_DEFAULTS["note"].size, defaults: WIDGET_DEFAULTS["note"].config, View: NoteTile, Settings: NoteSettings },
};

export function widgetTitle(widget: Widget): string {
  const custom = widget.config.title;
  if (typeof custom === "string" && custom.trim()) return custom.trim();
  if (widget.type === "number") return METRICS[str(widget.config, "metric", "agents.active", METRIC_KEYS)].label;
  if (widget.type === "breakdown") {
    return BREAKDOWN_TITLES[str(widget.config, "source", "compliance", BREAKDOWN_SOURCES)];
  }
  if (widget.type === "graph" && graphMetrics(widget.config).length === 1) return graphLabel(graphMetrics(widget.config)[0] ?? "alarms.active");
  return (widgetDefs as Partial<Record<string, WidgetDef>>)[widget.type]?.label ?? "Unsupported widget";
}
