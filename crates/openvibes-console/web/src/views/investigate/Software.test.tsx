// The Software list (approved screen 23), as markup (no DOM library in vitest;
// see ui/controls.test.tsx). Filters, saved views, columns and paging in a
// browser: e2e/demo/software-list.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/software", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { SoftwareList, SoftwareListRow } from "../../api/types";
import { SoftwareListBody, apiQuery, nameOf, softwareFilters } from "./Software";

const row = (over: Partial<SoftwareListRow> = {}): SoftwareListRow => ({
  name: "openssl", hosts: 12, versions: 3, rpm: true, dpkg: true, oldest: "3.0.9-2", newest: "3.2.2-6.fc44", advisories: 2, no_fix: 1, exploited: true, worst_severity: "critical",
  update_hosts: 5, used_by: [{ unit: "sshd.service", hosts: 12 }, { unit: "nginx.service", hosts: 3 }], used_by_total: 4, week_added: 2, week_updated: 1, week_removed: 0, ...over,
});
const list = (over: Partial<SoftwareList> = {}): SoftwareList => ({
  items: [
    row(),
    row({ name: "bash", hosts: 14, versions: 1, rpm: true, dpkg: false, oldest: "5.2.26-3", newest: "5.2.26-3", advisories: 0, no_fix: 0, exploited: false, update_hosts: 0, worst_severity: null,
      used_by: [], used_by_total: 0, week_added: 0, week_updated: 0, week_removed: 0 }),
    row({ name: "curl", versions: 1, oldest: "8.5.0-1", newest: "8.5.0-1", advisories: 1, no_fix: 1, exploited: false, update_hosts: 0, worst_severity: "moderate", week_added: 0, week_updated: 0, week_removed: 3 }),
  ],
  total: 3, generated_at: "2026-10-27T10:00:00Z",
  summary: { exploited: 1, fixable: 1, several_versions: 1, new_this_week: 1, reporting_hosts: 14 },
  counts: {
    vulns: [{ value: "exploited", count: 1 }, { value: "critical_high", count: 1 }, { value: "any", count: 2 }, { value: "none", count: 1 }], fix: [{ value: "available", count: 1 }, { value: "none", count: 2 }],
    versions: [{ value: "one", count: 2 }, { value: "several", count: 1 }], type: [{ value: "dpkg", count: 1 }, { value: "rpm", count: 3 }],
    changes: [{ value: "new", count: 1 }, { value: "updated", count: 1 }, { value: "removed", count: 1 }], group: [{ value: "g1", name: "Web", kind: "rule", count: 8 }],
  },
  ...over,
});
const render = (data: SoftwareList, hidden: string[] = [], offset = 0) =>
  renderToStaticMarkup(<SoftwareListBody list={data} hidden={hidden} offset={offset} />).replace(/<!-- -->/g, "");
const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/&#x27;/g, "'").replace(/\s+/g, " ");

describe("Software list", () => {
  it("asks the API only for what it reads, one page at a time", () => {
    expect(apiQuery(new URLSearchParams("q=ssl&vulns=any&fix=available&versions=several&type=rpm&group=g1&changes=new&host=a%2F1&sort=hosts&dir=desc&offset=50&bad=1&fixable=true")))
      .toBe("q=ssl&vulns=any&fix=available&versions=several&type=rpm&group=g1&changes=new&host=a%2F1&sort=hosts&dir=desc&offset=50&limit=50");
    expect(apiQuery(new URLSearchParams())).toBe("limit=50");
  });

  it("renders screen 23's columns, the package a real link to its page", () => {
    const html = render(list());
    for (const header of ["Package", "Hosts", "Versions", "Vulnerabilities", "Fix", "Used by", "This week"]) expect(html).toContain(`>${header}<`);
    expect(html).toContain('href="/software/openssl"');
    expect(html).toContain('href="/software/bash"');
    expect(text(html)).toContain("rpm + dpkg");
  });

  it("says versions, vulnerabilities, fix, used by and this week the way the rulings do", () => {
    const t = text(render(list()));
    expect(t).toContain("3.0.9-2 to 3.2.2-6.fc44");
    expect(t).toContain("3 versions");
    expect(t).toContain("1 version");
    expect(t).toContain("Exploited");
    expect(t).toContain("Update on 5");
    expect(t).toContain("No fix yet");
    expect(t).toContain("sshd");
    expect(t).toContain("+2");
    expect(t).toContain("+2 new");
    expect(t).toContain("1 updated");
    expect(t).toContain("−3");
    expect(t).toContain("No change");
  });

  it("links a service to its page", () => {
    expect(render(list())).toContain('href="/services/sshd.service"');
  });

  it("leaves out a hidden column but never Package", () => {
    const html = render(list(), ["package", "hosts", "versions", "vulnerabilities", "fix", "used_by", "week"]);
    expect(html).toContain(">Package<");
    for (const header of ["Hosts", "Versions", "Vulnerabilities", "Fix", "Used by", "This week"]) expect(html).not.toContain(`>${header}<`);
  });

  it("summarises from the server's counts and the reporting hosts", () => {
    expect(text(render(list()))).toContain("1 has an exploited vulnerability · 1 has an update available · 1 has several versions in use · 1 new this week · from 14 hosts' last reports");
  });

  it("pages by offset", () => {
    expect(render(list({ total: 120 }), [], 50)).toContain("51–53 of 120");
  });

  it("offers the filters the server counted, a group's count in hosts, and a Host chip only while set", () => {
    const filters = softwareFilters(list(), { host: null, hostName: undefined });
    expect(filters.map((f) => f.param)).toEqual(["vulns", "fix", "versions", "group", "type", "changes", "host"]);
    expect(filters.find((f) => f.param === "fix")?.values).toEqual([{ value: "available", label: "Update available", count: 1 }, { value: "none", label: "No fix yet", count: 2 }]);
    expect(filters.find((f) => f.param === "group")?.values).toEqual([{ value: "g1", label: "Web", count: 8, hint: "8 hosts" }]);
    expect(filters.find((f) => f.param === "host")?.values).toEqual([]);
    expect(softwareFilters(list(), { host: "agent-1", hostName: "web-01" }).find((f) => f.param === "host")?.values).toEqual([{ value: "agent-1", label: "web-01", count: 3 }]);
  });

  it("reads a package from /software/{name}", () => {
    expect(nameOf("/software/openssl")).toBe("openssl");
    expect(nameOf("/software/libstdc%2B%2B6")).toBe("libstdc++6");
    for (const bad of ["/software/", "/software/a/b", "/software/%E0%A4%A", "/software/a%00b"]) expect(nameOf(bad)).toBeNull();
  });
});
