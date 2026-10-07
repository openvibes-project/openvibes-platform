// The widget types a dashboard can hold. Adding one: an entry here, its
// type in layout.ts's WIDGET_TYPES, and the same name in the server's
// allow-list (openvibes-console/src/dashboards.rs).
import type { ReactNode } from "react";

import type { IconName } from "../ui/Icon";
import { str } from "./config";
import { WIDGET_DEFAULTS } from "./defaults";
import type { Widget, WidgetType } from "./layout";
import { AttentionTile, BreakdownTile, ListTile, METRIC_KEYS, METRICS, NumberTile, TopHostsTile } from "./tiles";
import { AttentionSettings, BreakdownSettings, ListSettings, NoteSettings, NoteTile, NumberSettings, TopHostsSettings, TrendSettings, TrendTile } from "./tiles2";

export type WidgetProps = { widget: Widget };
export type SettingsProps = { widget: Widget; onChange: (config: Widget["config"]) => void };
export type WidgetDef = {
  type: WidgetType; label: string; description: string; icon: IconName; size: { w: number; h: number };
  defaults: Widget["config"]; View: (props: WidgetProps) => ReactNode; Settings: (props: SettingsProps) => ReactNode;
};

export const widgetDefs: Readonly<Record<WidgetType, WidgetDef>> = {
  number: { type: "number", label: "Number", description: "One count that opens its list", icon: "activity", size: WIDGET_DEFAULTS["number"].size, defaults: WIDGET_DEFAULTS["number"].config, View: NumberTile, Settings: NumberSettings },
  breakdown: { type: "breakdown", label: "Breakdown", description: "A severity or status bar", icon: "filter", size: WIDGET_DEFAULTS["breakdown"].size, defaults: WIDGET_DEFAULTS["breakdown"].config, View: BreakdownTile, Settings: BreakdownSettings },
  attention: { type: "attention", label: "Needs attention", description: "Exploited, serious and silent, in one list", icon: "alert", size: WIDGET_DEFAULTS["attention"].size, defaults: WIDGET_DEFAULTS["attention"].config, View: AttentionTile, Settings: AttentionSettings },
  list: { type: "list", label: "List", description: "The first rows of any list, with its filters", icon: "findings", size: WIDGET_DEFAULTS["list"].size, defaults: WIDGET_DEFAULTS["list"].config, View: ListTile, Settings: ListSettings },
  trend: { type: "trend", label: "Trend", description: "Hosts reporting a compliance finding per day", icon: "activity", size: WIDGET_DEFAULTS["trend"].size, defaults: WIDGET_DEFAULTS["trend"].config, View: TrendTile, Settings: TrendSettings },
  "top-hosts": { type: "top-hosts", label: "Most exposed hosts", description: "Hosts with the most serious vulnerabilities", icon: "agents", size: WIDGET_DEFAULTS["top-hosts"].size, defaults: WIDGET_DEFAULTS["top-hosts"].config, View: TopHostsTile, Settings: TopHostsSettings },
  note: { type: "note", label: "Note", description: "Plain text for your team", icon: "help", size: WIDGET_DEFAULTS["note"].size, defaults: WIDGET_DEFAULTS["note"].config, View: NoteTile, Settings: NoteSettings },
};

export function widgetTitle(widget: Widget): string {
  const custom = widget.config.title;
  if (typeof custom === "string" && custom.trim()) return custom.trim();
  if (widget.type === "number") return METRICS[str(widget.config, "metric", "agents.active", METRIC_KEYS)].label;
  if (widget.type === "breakdown") {
    return { compliance: "Compliance findings by severity", vulnerabilities: "Vulnerabilities by severity", agents: "Hosts by status" }[str(widget.config, "source", "compliance", ["compliance", "vulnerabilities", "agents"] as const)];
  }
  return (widgetDefs as Partial<Record<string, WidgetDef>>)[widget.type]?.label ?? "Unsupported widget";
}
