import { describe, expect, it } from "vitest";

import { alarmPath, casePath, casesQuery, checkPath, complianceQuery, formatLocation, hostPath, hostsQuery, pagePath, parseLocation, popPanel, pushPanel, vulnerabilitiesQuery } from "./location";

// An old panel link opens the object's page, with no panel left.
const opensPage = (view: string, search: string, want: string) => {
  const loc = parseLocation(view, search, "/");
  expect(loc.panels).toEqual([]);
  expect(formatLocation(loc, "/")).toBe(want);
};

describe("location", () => {
  it("reads the view, panel stack and filters from a URL", () => {
    const loc = parseLocation("/console/compliance", "?open=package%3Ab%2FR-1&open=port%3Atcp%3A443&q=web", "/console/");
    expect(loc.view).toBe("/compliance");
    expect(loc.panels).toEqual([{ kind: "package", id: "b/R-1" }, { kind: "port", id: "tcp:443" }]);
    expect(loc.params.get("q")).toBe("web");
  });

  it("round-trips through formatLocation", () => {
    const loc = parseLocation("/compliance", "?open=finding-group%3Abaseline%2FOV-1&sev=high", "/");
    expect(formatLocation(loc, "/")).toBe("/compliance?sev=high&open=finding-group%3Abaseline%2FOV-1");
  });

  it("reads the old /findings page as /compliance, keeping its filters", () => {
    const loc = parseLocation("/console/findings", "?severity=high&open=port%3Atcp%3A443", "/console/");
    expect(formatLocation(loc, "/console/")).toBe("/console/compliance?severity=high&open=port%3Atcp%3A443");
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
    opensPage(view, search, want);
  });

  it.each([
    ["/vulnerabilities", "?open=advisory%3AFEDORA-2026-3a214d1f", "/vulnerabilities/FEDORA-2026-3a214d1f"],
    ["/", "?open=advisory%3ACVE-2026-1", "/vulnerabilities/CVE-2026-1"],
    ["/cases", "?status=open&open=case%3Ac-1&open=advisory%3ARHSA-2026%3A1", "/vulnerabilities/RHSA-2026%3A1"],
    // A host or an alarm panel still wins.
    ["/", "?open=advisory%3AX-1&open=alarm%3A7", "/alarms/7"],
  ])("old_advisory_links_open_the_page: an old advisory panel on %s%s is the vulnerability's page, %s", (view, search, want) => {
    opensPage(view, search, want);
  });

  it.each([
    ["/compliance", "?open=finding%3Abaseline%2Fport.ssh.exposed", "/compliance/baseline/port.ssh.exposed"],
    ["/findings", "?state=all&open=finding%3Ab%2FR-1", "/compliance/b/R-1"],
    ["/", "?open=finding%3Aa%2Fb%2Fc", "/compliance/a/b%2Fc"],
    ["/cases", "?status=open&open=case%3Ac-1&open=finding%3Ab%2FR-1", "/compliance/b/R-1"],
    // A finding from before rule sets (`agent//rule` in a case).
    ["/", "?open=finding%3A%2FLNX-1", "/compliance/~unknown/LNX-1"],
    // A host, an alarm or an advisory panel still wins.
    ["/", "?open=finding%3Ab%2FR-1&open=advisory%3AX-1", "/vulnerabilities/X-1"],
  ])("old_finding_links_open_the_page: an old finding panel on %s%s is the check's page, %s", (view, search, want) => {
    opensPage(view, search, want);
  });

  it("names the page an object opens instead of a panel", () => {
    expect(pagePath({ kind: "finding", id: "hardening-linux-l1/harden.ssh.permit_root_login" })).toBe("/compliance/hardening-linux-l1/harden.ssh.permit_root_login");
    expect(alarmPath("7 /x")).toBe("/alarms/7%20%2Fx");
    expect(pagePath({ kind: "alarm", id: "7" })).toBe("/alarms/7");
    expect(pagePath({ kind: "agent", id: "a b" })).toBe("/hosts/a%20b");
    expect(pagePath({ kind: "advisory", id: "X 1" })).toBe("/vulnerabilities/X%201");
    expect(pagePath({ kind: "package", id: "x" })).toBeNull();
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

  it.each([
    ["?exploited=true", "/vulnerabilities?signal=exploited"],
    ["?state=all&reboot=true&q=ssl", "/vulnerabilities?state=all&q=ssl&signal=reboot"],
    ["?nofix=true", "/vulnerabilities?signal=nofix"],
    ["?lowconf=true&severity=critical", "/vulnerabilities?severity=critical&signal=lowconf"],
    // Several old flags: the first in ruling 7's order wins.
    ["?lowconf=true&nofix=true&reboot=true&exploited=true", "/vulnerabilities?signal=exploited"],
    ["?nofix=true&lowconf=true", "/vulnerabilities?signal=nofix"],
    ["?severity=important&sort=cvss&dir=desc", "/vulnerabilities?severity=important&sort=cvss&dir=desc"],
  ])("old_vulnerability_urls_keep_their_filters: /vulnerabilities%s reads as %s", (search, want) => {
    expect(formatLocation(parseLocation("/vulnerabilities", search, "/"), "/")).toBe(want);
  });

  it("maps an old Vulnerabilities query's flags and sorts, and keeps today's", () => {
    expect(vulnerabilitiesQuery("exploited=true&sort=priority&dir=asc")).toBe("signal=exploited");
    expect(vulnerabilitiesQuery("q=x&sort=title&dir=desc")).toBe("q=x");
    expect(vulnerabilitiesQuery("sort=confidence")).toBe("");
    expect(vulnerabilitiesQuery("sort=hosts&dir=desc&exploited=false")).toBe("sort=hosts&dir=desc");
    expect(vulnerabilitiesQuery("signal=due30&package=openssl")).toBe("signal=due30&package=openssl");
  });

  it.each([
    // Ruling 9: state=all and severity keep their meaning; the old window (and its since) goes.
    ["?state=all&severity=high", "/compliance?state=all&severity=high"],
    ["?host=agent-1&window=all", "/compliance?host=agent-1"],
    ["?since=2026-01-01T00%3A00%3A00Z&q=ssh", "/compliance?q=ssh"],
    // The old rule-set chip is today's Rule set filter.
    ["?set=baseline", "/compliance?rule_set=baseline"],
    // Sorts no column has any more go with their direction; today's stay.
    ["?sort=active&dir=desc&severity=low", "/compliance?severity=low"],
    ["?sort=failing&dir=asc", "/compliance?sort=failing&dir=asc"],
  ])("old_compliance_urls_keep_their_meaning: /compliance%s reads as %s", (search, want) => {
    expect(formatLocation(parseLocation("/compliance", search, "/"), "/")).toBe(want);
  });

  it("maps an old Compliance query and leaves today's alone", () => {
    expect(complianceQuery("window=all&set=hardening-linux-l1&sort=last")).toBe("rule_set=hardening-linux-l1");
    expect(complianceQuery("rule_set=site&area=SSH&sort=check&dir=desc")).toBe("rule_set=site&area=SSH&sort=check&dir=desc");
    // The old /findings address reads as /compliance and maps too.
    expect(formatLocation(parseLocation("/findings", "?set=baseline&window=all", "/"), "/")).toBe("/compliance?rule_set=baseline");
  });

  it("maps an old Cases query and leaves today's alone (roles 5d)", () => {
    // The old Unassigned chip was assignee=none; status, severity, me and q keep their meaning.
    expect(casesQuery("status=all&severity=high&assignee=none&q=ssh")).toBe("status=all&severity=high&assignee=unassigned&q=ssh");
    expect(casesQuery("assignee=me&status=closed")).toBe("assignee=me&status=closed");
    // The old list sorted in the browser by any column; today's sorts by case, severity and updated only.
    expect(casesQuery("sort=title&dir=asc")).toBe("");
    expect(casesQuery("sort=number&dir=asc")).toBe("sort=case&dir=asc");
    expect(casesQuery("sort=updated&dir=asc&contains=alarms")).toBe("sort=updated&dir=asc&contains=alarms");
    expect(formatLocation(parseLocation("/cases", "?assignee=none", "/"), "/")).toBe("/cases?assignee=unassigned");
  });

  it("names a case's page", () => {
    expect(casePath("c-1/x")).toBe("/cases/c-1%2Fx");
  });

  it("names a check's page by its rule set and rule", () => {
    expect(checkPath("hardening-linux-l1", "harden.ssh.permit_root_login")).toBe("/compliance/hardening-linux-l1/harden.ssh.permit_root_login");
    expect(checkPath("a/b", "c d")).toBe("/compliance/a%2Fb/c%20d");
    expect(checkPath("", "ssh.root_login")).toBe("/compliance/~unknown/ssh.root_login");
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
