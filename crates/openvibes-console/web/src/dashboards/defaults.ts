// Starting size and settings of each widget type. Plain data (no React), so
// the editor store can use it anywhere, including in unit tests.
import type { Widget, WidgetType } from "./layout";

export const WIDGET_DEFAULTS: Readonly<Record<WidgetType, { size: { w: number; h: number }; config: Widget["config"] }>> = {
  number: { size: { w: 3, h: 2 }, config: { metric: "compliance.open.critical", trend: 0 } },
  breakdown: { size: { w: 4, h: 3 }, config: { source: "compliance" } },
  attention: { size: { w: 7, h: 7 }, config: { include: ["exploited", "compliance", "stale"], limit: 8 } },
  list: { size: { w: 6, h: 6 }, config: { view: "/compliance", query: "severity=critical", limit: 8 } },
  trend: { size: { w: 4, h: 3 }, config: { finding: "", days: 14 } },
  "top-hosts": { size: { w: 5, h: 6 }, config: { limit: 6 } },
  note: { size: { w: 4, h: 3 }, config: { text: [] } },
};
