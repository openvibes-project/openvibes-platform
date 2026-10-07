// Dashboards saved before the compliance rename (schema migration 43) can
// still arrive from a browser draft; map their IDs like the migration does.
import type { Layout } from "./layout";

export function upgradeLayout(layout: Layout): Layout {
  return { ...layout, widgets: layout.widgets.map((w) => {
    const c: Record<string, unknown> = { ...w.config };
    if (typeof c.metric === "string" && c.metric.startsWith("findings.open.")) c.metric = `compliance.open.${c.metric.slice(14)}`;
    if (c.source === "findings") c.source = "compliance";
    if (c.view === "/findings") c.view = "/compliance";
    if (Array.isArray(c.include)) c.include = c.include.map((k) => (k === "findings" ? "compliance" : k));
    return { ...w, config: c as typeof w.config };
  }) };
}
