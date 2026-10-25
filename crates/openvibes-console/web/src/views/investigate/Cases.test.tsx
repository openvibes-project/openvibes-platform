// The Cases list (approved screen 31), as markup (no DOM library in vitest;
// see ui/controls.test.tsx). Filters, saved views and columns in a browser:
// e2e/demo/case-list.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/cases", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { CaseList, CaseListRow } from "../../api/types";
import { CaseListBody, apiQuery, caseFilters, caseIdOf } from "./Cases";

const user = (id: string, name: string) => ({ user_id: id, username: id, display_name: name });
const row = (over: Partial<CaseListRow> = {}): CaseListRow => ({
  case_id: "c-104", number: 104, title: "Shells started by nginx on web-01", status: "investigating", severity: "high",
  opened_by: user("u-sam", "Sam Analyst"), assignee: user("u-sam", "Sam Analyst"),
  latest_note: { text: "One command is the health check; sh -c id is not ours.", at: "2026-10-25T08:00:00Z" },
  hosts: [{ agent_id: "a-1", hostname: "web-01" }], host_count: 1,
  kinds: { alarms: 2, findings: 0, vulnerabilities: 1, hosts: 0, software: 0 }, with_outcome: 1, takes_outcome: 3, ready: false,
  updated_at: "2026-10-25T08:10:00Z", ...over,
});
const list = (over: Partial<CaseList> = {}): CaseList => ({
  items: [
    row(),
    row({ case_id: "c-103", number: 103, title: "PostgreSQL started a shell on db-02", status: "open", severity: "critical", assignee: null, latest_note: null,
      hosts: ["db-01", "db-02", "db-03", "db-04", "db-05"].map((h) => ({ agent_id: h, hostname: h })), host_count: 8,
      kinds: { alarms: 1, findings: 1, vulnerabilities: 0, hosts: 1, software: 0 }, with_outcome: 2, takes_outcome: 2, ready: true }),
    row({ case_id: "c-90", number: 90, title: "Empty", hosts: [], host_count: 0, latest_note: null,
      kinds: { alarms: 0, findings: 0, vulnerabilities: 0, hosts: 0, software: 0 }, with_outcome: 0, takes_outcome: 0, ready: true }),
  ],
  total: 3, generated_at: "2026-10-25T10:00:00Z",
  summary: { open: 1, investigating: 2, unassigned: 1, ready_to_close: 2 },
  counts: {
    status: [{ value: "active", count: 3 }, { value: "open", count: 1 }, { value: "investigating", count: 2 }, { value: "closed", count: 4 }, { value: "all", count: 7 }],
    severity: [{ value: "critical", count: 1 }, { value: "high", count: 2 }, { value: "medium", count: 0 }, { value: "low", count: 0 }],
    contains: [{ value: "alarms", count: 2 }, { value: "vulnerabilities", count: 1 }, { value: "findings", count: 1 }],
    updated: [{ value: "today", count: 3 }, { value: "week", count: 3 }, { value: "quiet", count: 0 }],
    group: [{ value: "g1", name: "Web", kind: "manual", count: 1 }],
    assignee: { me: 1, unassigned: 1, people: [{ value: "u-sam", name: "Sam Analyst", count: 2 }] },
  },
  ...over,
});
const render = (data: CaseList, hidden: string[] = [], status: string | null = null) =>
  renderToStaticMarkup(<CaseListBody list={data} hidden={hidden} status={status} />).replace(/<!-- -->/g, "");

describe("Cases list", () => {
  it("asks the API only for what it reads, in its spelling, one page at a time", () => {
    expect(apiQuery(new URLSearchParams("q=ssh&status=all&contains=alarms&updated=quiet&host=a%2F1&group=g&assignee=me&severity=high&offset=50&sort=case&dir=asc&open=case%3Ax&bad=1")))
      .toBe("q=ssh&status=all&severity=high&assignee=me&contains=alarms&host=a%2F1&group=g&updated=quiet&dir=asc&offset=50&sort=number&limit=50");
    // A column the API can't sort by sends no sort: the API's default (updated).
    expect(apiQuery(new URLSearchParams("sort=title"))).toBe("limit=50");
  });

  it("renders screen 31's columns, the title a real link to the case's page", () => {
    const html = render(list());
    for (const header of ["Case", "Title", "Severity", "Status", "Assignee", "Hosts", "Items", "Updated"]) expect(html).toContain(`>${header}<`);
    expect(html).toContain("C-104");
    expect(html).toMatch(/<a [^>]*href="\/cases\/c-104"[^>]*><span class="sr-only">C-104 <\/span>Shells started by nginx on web-01<\/a>/);
    expect(html).toContain("Opened by Sam Analyst");
    expect(html).toContain("Investigating");
    expect(html).toContain("Unassigned");
  });

  it("says how an old closed case ended in Status, a new close only Closed", () => {
    const html = render(list({ items: [row({ status: "closed", resolution: "mitigated" }), row({ case_id: "c-2", number: 2, status: "closed", resolution: null })] }), [], "all");
    expect(html).toContain("Closed · mitigated");
    expect(html.match(/>Closed</g)).toHaveLength(1);
  });

  it("shows the latest note, named for screen readers", () => {
    const html = render(list());
    expect(html).toContain('<span class="sr-only">Latest note, </span>');
    expect(html).toContain("“One command is the health check; sh -c id is not ours.”");
  });

  it("names up to five hosts, each a link to its page, and how many more", () => {
    const html = render(list());
    expect(html).toContain('href="/hosts/a-1"');
    expect(html).toContain(">db-05</a>");
    expect(html).toContain("+3<span class=\"sr-only\"> more hosts</span>");
  });

  it("counts the items by kind and how many have an outcome, in words and a bar named for screen readers", () => {
    const html = render(list());
    expect(html).toContain('title="2 alarms"');
    expect(html).toContain('title="1 vulnerability"');
    expect(html).toContain('<span class="sr-only"> alarms</span>');
    expect(html).toMatch(/role="progressbar"[^>]*aria-valuetext="1 of 3 with an outcome"/);
    expect(html).toContain("1/3 with an outcome");
  });

  it('says "Ready to close" when the case is, and "No items" on an empty case', () => {
    const html = render(list());
    expect(html.match(/Ready to close/g)).toHaveLength(2);
    expect(html).toContain("No items");
  });

  it("leaves out hidden columns, never Case or Title", () => {
    const html = render(list(), ["hosts", "updated", "case", "title"]);
    expect(html).not.toContain(">Hosts<");
    expect(html).not.toContain(">Updated<");
    expect(html).toContain(">Case<");
    expect(html).toContain(">Title<");
  });

  it("says ruling 10's summary line, and that closed cases are hidden by default", () => {
    expect(render(list())).toContain("1 open · 2 investigating · 1 unassigned · 2 ready to close · closed cases hidden");
    expect(render(list(), [], "all")).toContain("2 ready to close</p>");
  });

  it("offers every filter of screen 31, Host only while set", () => {
    const filters = caseFilters(list(), { host: "a-1", hostName: "web-01" });
    expect(filters.map((f) => f.label)).toEqual(["Status", "Severity", "Assignee", "Contains", "Host", "Group", "Updated"]);
    expect(filters.find((f) => f.param === "status")?.values.map((v) => [v.label, v.count])).toEqual([["Open", 1], ["Investigating", 2], ["Closed", 4], ["All statuses", 7]]);
    expect(filters.find((f) => f.param === "contains")?.values.map((v) => v.label)).toEqual(["Alarms", "Vulnerabilities", "Compliance findings"]);
    expect(filters.find((f) => f.param === "updated")?.values.map((v) => v.label)).toEqual(["Today", "This week", "Quiet for 7 days or more"]);
    expect(filters.find((f) => f.param === "assignee")?.values.map((v) => v.label)).toEqual(["Me", "Unassigned", "Sam Analyst"]);
    expect(filters.find((f) => f.param === "group")?.values.map((v) => v.label)).toEqual(["Web"]);
    expect(filters.find((f) => f.param === "host")).toMatchObject({ chipOnly: true, values: [{ value: "a-1", label: "web-01" }] });
    expect(caseFilters(list(), { host: null, hostName: undefined }).find((f) => f.param === "host")?.values).toEqual([]);
  });

  it("reads the case id from /cases/{id}, nothing from other paths", () => {
    expect(caseIdOf("/cases/c-104")).toBe("c-104");
    expect(caseIdOf("/cases/a%2Fb")).toBe("a/b");
    expect(caseIdOf("/cases/")).toBeNull();
    expect(caseIdOf("/cases/a/b")).toBeNull();
    expect(caseIdOf("/cases/%E0")).toBeNull();
  });
});
