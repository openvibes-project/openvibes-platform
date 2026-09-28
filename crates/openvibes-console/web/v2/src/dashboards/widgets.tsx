// The widget types a dashboard can hold. Adding one: an entry here, its
// type in layout.ts's WIDGET_TYPES, and the same name in the server's
// allow-list (openvibes-console/src/dashboards.rs).
import type { ReactNode } from "react";

import type { IconName } from "../ui/Icon";
import type { Widget, WidgetType } from "./layout";
import { AttentionTile, BreakdownTile, ListTile, NumberTile, TopHostsTile } from "./tiles";
import { AttentionSettings, BreakdownSettings, ListSettings, NoteSettings, NoteTile, NumberSettings, TopHostsSettings, TrendSettings, TrendTile } from "./tiles2";

export type WidgetProps = { widget: Widget };
export type SettingsProps = { widget: Widget; onChange: (config: Widget["config"]) => void };
export type WidgetDef = {
  type: WidgetType; label: string; description: string; icon: IconName; size: { w: number; h: number };
  defaults: Widget["config"]; View: (props: WidgetProps) => ReactNode; Settings: (props: SettingsProps) => ReactNode;
};

export const widgetDefs: Readonly<Record<WidgetType, WidgetDef>> = {
  number: { type: "number", label: "Number", description: "One count that opens its list", icon: "activity", size: { w: 3, h: 2 }, defaults: { metric: "findings.open.critical" }, View: NumberTile, Settings: NumberSettings },
  breakdown: { type: "breakdown", label: "Breakdown", description: "A severity or status bar", icon: "filter", size: { w: 4, h: 3 }, defaults: { source: "findings" }, View: BreakdownTile, Settings: BreakdownSettings },
  attention: { type: "attention", label: "Needs attention", description: "Exploited, serious and silent, in one list", icon: "alert", size: { w: 7, h: 7 }, defaults: { include: ["exploited", "findings", "stale"], limit: 8 }, View: AttentionTile, Settings: AttentionSettings },
  list: { type: "list", label: "List", description: "The first rows of any list, with its filters", icon: "findings", size: { w: 6, h: 6 }, defaults: { view: "/findings", query: "severity=critical", limit: 8 }, View: ListTile, Settings: ListSettings },
  trend: { type: "trend", label: "Trend", description: "Hosts reporting a finding per day", icon: "activity", size: { w: 4, h: 3 }, defaults: { finding: "", days: 14 }, View: TrendTile, Settings: TrendSettings },
  "top-hosts": { type: "top-hosts", label: "Most exposed hosts", description: "Hosts with the most serious vulnerabilities", icon: "agents", size: { w: 5, h: 6 }, defaults: { limit: 6 }, View: TopHostsTile, Settings: TopHostsSettings },
  note: { type: "note", label: "Note", description: "Plain text for your team", icon: "help", size: { w: 4, h: 3 }, defaults: { text: [] }, View: NoteTile, Settings: NoteSettings },
};

export function widgetTitle(widget: Widget): string {
  const custom = widget.config.title;
  return typeof custom === "string" && custom.trim() ? custom.trim() : widgetDefs[widget.type].label;
}
