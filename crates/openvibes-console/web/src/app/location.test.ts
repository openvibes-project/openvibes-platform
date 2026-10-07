import { describe, expect, it } from "vitest";

import { parseLocation, formatLocation, pushPanel, popPanel } from "./location";

describe("location", () => {
  it("reads the view, panel stack and filters from a URL", () => {
    const loc = parseLocation("/console/agents", "?open=agent%3Aagent-1&open=advisory%3ARHSA-2026%3A1&q=web", "/console/");
    expect(loc.view).toBe("/agents");
    expect(loc.panels).toEqual([{ kind: "agent", id: "agent-1" }, { kind: "advisory", id: "RHSA-2026:1" }]);
    expect(loc.params.get("q")).toBe("web");
  });

  it("round-trips through formatLocation", () => {
    const loc = parseLocation("/compliance", "?open=finding-group%3Abaseline%2FOV-1&sev=high", "/");
    expect(formatLocation(loc, "/")).toBe("/compliance?sev=high&open=finding-group%3Abaseline%2FOV-1");
  });

  it("reads the old /findings page as /compliance, keeping its filters", () => {
    const loc = parseLocation("/console/findings", "?severity=high&open=finding%3Ab%2FR-1", "/console/");
    expect(formatLocation(loc, "/console/")).toBe("/console/compliance?severity=high&open=finding%3Ab%2FR-1");
  });

  it("ignores malformed panel references", () => {
    expect(parseLocation("/", "?open=nokind&open=%3Aid&open=agent%3A", "/").panels).toEqual([]);
  });

  it("pushes a new panel, and re-opening one already on the stack returns to it", () => {
    const base = parseLocation("/", "", "/");
    const one = pushPanel(base, { kind: "agent", id: "a" });
    const two = pushPanel(one, { kind: "advisory", id: "x" });
    expect(two.panels).toHaveLength(2);
    expect(pushPanel(two, { kind: "agent", id: "a" }).panels).toEqual([{ kind: "agent", id: "a" }]);
    expect(popPanel(two).panels).toEqual([{ kind: "agent", id: "a" }]);
  });

  it("replaces the stack when asked to open from a list", () => {
    const two = pushPanel(pushPanel(parseLocation("/", "", "/"), { kind: "agent", id: "a" }), { kind: "advisory", id: "x" });
    expect(pushPanel(two, { kind: "agent", id: "b" }, true).panels).toEqual([{ kind: "agent", id: "b" }]);
  });
});
