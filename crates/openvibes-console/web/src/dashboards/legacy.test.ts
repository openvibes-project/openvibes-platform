import { describe, expect, it } from "vitest";
import { upgradeLayout } from "./legacy";

describe("upgradeLayout", () => {
  it("maps pre-0.2.6 finding IDs to compliance IDs and leaves the rest", () => {
    const old = { schema: 1, widgets: [
      { id: "a", type: "number", x: 0, y: 0, w: 3, h: 2, config: { metric: "findings.open.critical" } },
      { id: "b", type: "breakdown", x: 0, y: 0, w: 3, h: 2, config: { source: "findings" } },
      { id: "c", type: "attention", x: 0, y: 0, w: 3, h: 2, config: { include: ["alarms", "findings"] } },
      { id: "d", type: "list", x: 0, y: 0, w: 3, h: 2, config: { view: "/findings", query: "severity=high" } },
      { id: "e", type: "number", x: 0, y: 0, w: 3, h: 2, config: { metric: "alarms.active" } },
    ] } as const;
    const up = upgradeLayout(structuredClone(old) as never);
    expect(up.widgets.map((w) => w.config)).toEqual([
      { metric: "compliance.open.critical" }, { source: "compliance" }, { include: ["alarms", "compliance"] },
      { view: "/compliance", query: "severity=high" }, { metric: "alarms.active" },
    ]);
  });
});
