// The built-in Overview: not stored, not editable, updated with releases.
// "Duplicate to edit" makes a stored copy of this layout.
import type { Layout } from "./layout";

export const BUILTIN_ID = "overview";
export const BUILTIN_NAME = "Overview";
export const BUILTIN_LAYOUT: Layout = {
  schema: 1,
  widgets: [
    { id: "online", type: "number", x: 0, y: 0, w: 2, h: 2, config: { metric: "agents.active" } },
    { id: "stale", type: "number", x: 2, y: 0, w: 2, h: 2, config: { metric: "agents.stale" } },
    { id: "critical", type: "number", x: 4, y: 0, w: 2, h: 2, config: { metric: "findings.open.critical" } },
    { id: "high", type: "number", x: 6, y: 0, w: 2, h: 2, config: { metric: "findings.open.high" } },
    { id: "exploited", type: "number", x: 8, y: 0, w: 2, h: 2, config: { metric: "vulns.exploited" } },
    { id: "reboot", type: "number", x: 10, y: 0, w: 2, h: 2, config: { metric: "vulns.reboot_hosts" } },
    { id: "attention", type: "attention", x: 0, y: 2, w: 7, h: 9, config: { include: ["exploited", "findings", "stale"], limit: 14 } },
    { id: "findings", type: "breakdown", x: 7, y: 2, w: 5, h: 2, config: { source: "findings" } },
    { id: "hosts", type: "top-hosts", x: 7, y: 4, w: 5, h: 7, config: { limit: 7 } },
  ],
};
