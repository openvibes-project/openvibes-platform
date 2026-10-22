import { describe, expect, it } from "vitest";

import { alarmPath, formatLocation, hostPath, hostsQuery, pagePath, parseLocation, popPanel, pushPanel } from "./location";

describe("location", () => {
  it("reads the view, panel stack and filters from a URL", () => {
    const loc = parseLocation("/console/compliance", "?open=finding%3Ab%2FR-1&open=advisory%3ARHSA-2026%3A1&q=web", "/console/");
    expect(loc.view).toBe("/compliance");
    expect(loc.panels).toEqual([{ kind: "finding", id: "b/R-1" }, { kind: "advisory", id: "RHSA-2026:1" }]);
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
    ["?q=web&open=agent%3Aagent-00005&open=advisory%3AX-1", "/hosts/agent-00005"],
  ])("reads the old /agents%s as %s", (search, want) => {
    expect(formatLocation(parseLocation("/console/agents", search, "/console/"), "/console/")).toBe(`/console${want}`);
  });

  it.each([
    ["/alarms", "?q=web&open=alarm%3A7&open=agent%3Aweb%2001", "/hosts/web%2001"],
    ["/compliance", "?open=agent%3Aagent-1&open=advisory%3AX-1", "/hosts/agent-1"],
  ])("reads an old host panel on %s%s as the host's page, %s", (view, search, want) => {
    expect(formatLocation(parseLocation(view, search, "/"), "/")).toBe(want);
  });

  it.each([
    ["/alarms", "?open=alarm%3A7", "/alarms/7"],
    ["/", "?open=alarm%3A9000", "/alarms/9000"],
    ["/cases", "?status=open&open=case%3Ac-1&open=alarm%3A12", "/alarms/12"],
  ])("old_alarm_links_open_the_page: an old alarm panel on %s%s is the alarm's page, %s", (view, search, want) => {
    const loc = parseLocation(view, search, "/");
    expect(loc.panels).toEqual([]);
    expect(formatLocation(loc, "/")).toBe(want);
  });

  it("names the page an object opens instead of a panel", () => {
    expect(alarmPath("7 /x")).toBe("/alarms/7%20%2Fx");
    expect(pagePath({ kind: "alarm", id: "7" })).toBe("/alarms/7");
    expect(pagePath({ kind: "agent", id: "a b" })).toBe("/hosts/a%20b");
    expect(pagePath({ kind: "advisory", id: "X-1" })).toBeNull();
  });

  it("names a host's page", () => {
    expect(hostPath("web 01/a")).toBe("/hosts/web%2001%2Fa");
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
