// The built-in Overview: not stored, not editable, updated with releases.
// "Duplicate to edit" makes a stored copy of this layout.
import type { Layout } from "./layout";

export const BUILTIN_ID = "overview";
export const BUILTIN_NAME = "Overview";
export const BUILTIN_LAYOUT: Layout = {
  schema: 1,
  // Most important first and to the left (the user, #116): what needs
  // action now on top, the fleet's housekeeping in its own row below.
  widgets: [
    { id: "alarms", type: "number", x: 0, y: 0, w: 3, h: 4, config: { metric: "alarms.active", trend: 30, line: "smooth" } },
    { id: "critical", type: "number", x: 3, y: 0, w: 3, h: 4, config: { metric: "all.open.critical", trend: 30, line: "smooth" } },
    { id: "high", type: "number", x: 6, y: 0, w: 3, h: 4, config: { metric: "all.open.high", trend: 30, line: "smooth" } },
    { id: "exploited", type: "number", x: 9, y: 0, w: 3, h: 4, config: { metric: "vulns.exploited", trend: 30, line: "smooth" } },
    { id: "attention", type: "attention", x: 0, y: 4, w: 7, h: 9, config: { include: ["alarms", "exploited", "serious", "compliance", "stale"], limit: 14 } },
    { id: "vulns", type: "breakdown", x: 7, y: 4, w: 5, h: 2, config: { source: "vulnerabilities" } },
    { id: "compliance", type: "breakdown", x: 7, y: 6, w: 5, h: 2, config: { source: "compliance" } },
    { id: "hosts", type: "top-hosts", x: 7, y: 8, w: 5, h: 5, config: { limit: 7, kinds: "all" } },
    { id: "online", type: "number", x: 0, y: 13, w: 4, h: 2, config: { metric: "agents.active", title: "Fleet · online" } },
    { id: "stale", type: "number", x: 4, y: 13, w: 4, h: 2, config: { metric: "agents.stale", title: "Fleet · stale" } },
    { id: "reboot", type: "number", x: 8, y: 13, w: 4, h: 2, config: { metric: "vulns.reboot_hosts", title: "Fleet · need a reboot" } },
  ],
};
