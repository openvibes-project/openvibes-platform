import { describe, expect, it } from "vitest";

import { formatLocation, hostsQuery, parseLocation, popPanel, pushPanel } from "./location";

describe("location", () => {
  it("reads the view, panel stack and filters from a URL", () => {
    const loc = parseLocation("/console/alarms", "?open=agent%3Aagent-1&open=advisory%3ARHSA-2026%3A1&q=web", "/console/");
    expect(loc.view).toBe("/alarms");
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

  it.each([
    ["?status=stale&q=web", "/hosts?status=offline&q=web"],
    ["?status=active&sort=host", "/hosts?status=online&sort=host"],
    ["?open=agent%3Aagent-00005", "/hosts/agent-00005"],
    ["?agent=agent-00005", "/hosts/agent-00005"],
    ["?q=web&open=agent%3Aagent-00005&open=advisory%3AX-1", "/hosts/agent-00005?open=advisory%3AX-1"],
  ])("reads the old /agents%s as %s", (search, want) => {
    expect(formatLocation(parseLocation("/console/agents", search, "/console/"), "/console/")).toBe(`/console${want}`);
  });

  it("maps an old Hosts query's status values and keeps the rest", () => {
    expect(hostsQuery("status=active&q=web&bad=1")).toBe("status=online&q=web&bad=1");
    expect(hostsQuery("status=revoked")).toBe("status=revoked");
    expect(hostsQuery("sort=seen&dir=desc")).toBe("sort=heartbeat&dir=desc");
    expect(hostsQuery("sort=version")).toBe("sort=agent");
    expect(hostsQuery("q=x&sort=enrolled&dir=desc")).toBe("q=x");
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
