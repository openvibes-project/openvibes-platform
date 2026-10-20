// The Alarms list (approved screen 29), as markup (no DOM library in vitest;
// see ui/controls.test.tsx). Filters, saved views, columns and the bulk bar:
// e2e/demo/alarm-list.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/alarms", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { AlarmList, AlarmListRow } from "../../api/types";
import { AlarmListBody, alarmFilters, alarmIdOf, apiQuery } from "./Alarms";

const row = (over: Partial<AlarmListRow> = {}): AlarmListRow => ({
  id: 9000, host: { id: "agent-1", name: "web-01", os_family: "linux", distribution: "Debian 12" },
  rule_set_id: "baseline", rule_id: "web-server-spawns-shell", severity: "high", message: "A web server started a shell",
  program: "/usr/bin/sh", parent_program: "/usr/sbin/nginx", techniques: ["T1059.004", "T1505.003"], count: 3,
  first_seen: "2026-10-20T09:00:00Z", last_seen: "2026-10-20T10:00:00Z", state: "open",
  assignee: { id: "u-sam", name: "Sam Lee" }, case: { id: "c1", number: 104 }, suppressed: false, ...over,
});
const list = (over: Partial<AlarmList> = {}): AlarmList => ({
  items: [row(), row({ id: 9001, host: { id: "agent-2", name: null, os_family: "windows", distribution: null }, parent_program: null,
    techniques: [], assignee: null, case: null, state: "false_positive" })],
  total: 2, generated_at: "2026-10-20T10:00:00Z",
  summary: { open: 5, critical_or_high: 2, on_alarms_off_hosts: 1 },
  counts: {
    state: [{ value: "open", count: 5 }, { value: "mitigated", count: 1 }], severity: [{ value: "high", count: 2 }],
    suppressed: [{ value: "hidden", count: 5 }, { value: "shown", count: 6 }], case: [{ value: "yes", count: 1 }, { value: "no", count: 4 }],
    group: [{ value: "g1", name: "Web", kind: "manual", count: 2 }], technique: [{ value: "T1059.004", count: 3 }],
    assignee: { me: 1, unassigned: 3, people: [{ value: "u-sam", name: "Sam Lee", count: 1 }] },
  },
  ...over,
});
const render = (data: AlarmList, hidden: string[] = []) =>
  renderToStaticMarkup(<AlarmListBody list={data} hidden={hidden} selected={new Set()} onSelect={() => undefined} />).replace(/<!-- -->/g, "");

describe("Alarms list", () => {
  it("asks the API only for what it reads, in its spelling, one page at a time", () => {
    expect(apiQuery(new URLSearchParams("q=sh&severity=high&host=a%2F1&technique=T1059.004&window=7d&offset=50&sort=seen&dir=asc")))
      .toBe("q=sh&severity=high&host=a%2F1&technique=T1059.004&dir=asc&offset=50&sort=last_seen&limit=50");
    expect(apiQuery(new URLSearchParams("sort=count"))).toBe("sort=count&limit=50");
    // Old links: "include suppressed" was suppressed=true.
    expect(apiQuery(new URLSearchParams("suppressed=true"))).toBe("suppressed=shown&limit=50");
  });

  it("renders screen 29's columns: the message a real link to the alarm's page, chain and technique, host with OS, case and assignee", () => {
    const html = render(list());
    for (const header of ["Severity", "Alarm", "Host", "Count", "Seen", "State", "Assignee", "Case"]) expect(html).toContain(`>${header}<`);
    expect(html).toContain('href="/alarms/9000"');
    expect(html).toContain("nginx → sh");
    expect(html).toContain("T1059.004");
    expect(html).toContain("web-01");
    expect(html).toContain("Debian 12");
    expect(html).toContain("agent-2");
    expect(html).toContain("Windows");
    expect(html).toContain("C-104");
    expect(html).toContain("Sam Lee");
    expect(html).toContain("False positive");
  });

  it("has no per-row Suppress… (it is in the bulk bar and on the alarm's page)", () => {
    expect(render(list())).not.toContain("Suppress");
  });

  it("leaves out hidden columns, never Severity", () => {
    const html = render(list(), ["case", "assignee", "severity"]);
    expect(html).not.toContain(">Case<");
    expect(html).not.toContain(">Assignee<");
    expect(html).toContain(">Severity<");
  });

  it("says the summary line, without the alarms-off part when it is not given", () => {
    expect(render(list())).toContain("5 open · 2 critical or high · 1 on hosts with alarms off");
    const html = render(list({ summary: { open: 5, critical_or_high: 2, on_alarms_off_hosts: null } }));
    expect(html).toContain("5 open · 2 critical or high<");
  });

  it("offers every filter of screen 29, Suppressed and Host among them", () => {
    const filters = alarmFilters(list(), "agent-1", "web-01");
    expect(filters.map((f) => f.label)).toEqual(["Severity", "State", "Suppressed", "Host", "Group", "Technique", "Case", "Assignee"]);
    expect(filters.find((f) => f.param === "host")).toMatchObject({ chipOnly: true, values: [{ value: "agent-1", label: "web-01" }] });
    expect(filters.find((f) => f.param === "state")?.values.map((v) => v.label)).toEqual(["Open", "Mitigated", "All states"]);
    expect(filters.find((f) => f.param === "assignee")?.values.map((v) => v.label)).toEqual(["Me", "Unassigned", "Sam Lee"]);
    expect(filters.find((f) => f.param === "case")?.values.map((v) => v.label)).toEqual(["In a case", "Not in a case"]);
  });

  it("reads the alarm id from /alarms/{id}, nothing from other paths", () => {
    expect(alarmIdOf("/alarms/9000")).toBe("9000");
    expect(alarmIdOf("/alarms/9000/x")).toBeNull();
    expect(alarmIdOf("/alarms/%E0")).toBeNull();
    expect(alarmIdOf("/alarms/")).toBeNull();
  });
});
