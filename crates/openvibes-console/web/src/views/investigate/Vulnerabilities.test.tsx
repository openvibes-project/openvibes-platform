// The Vulnerabilities list (approved screen 25), as markup (no DOM library in
// vitest; see ui/controls.test.tsx). Filters, saved views, columns and the
// bulk bar in a browser: e2e/demo/vuln-list.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/vulnerabilities", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { Session, VulnList, VulnListRow } from "../../api/types";
import { SessionContext } from "../../app/session";
import { BulkBar } from "../../panels/triage/BulkBar";
import { VulnListBody, apiQuery, bulkItems, listBulk, vulnFilters, vulnKeyOf } from "./Vulnerabilities";
import { bulkReach } from "./vulnerability/Reach";

const DAY = 86_400_000;
const day = (offset: number) => new Date(Date.now() + offset * DAY).toISOString().slice(0, 10);
const row = (over: Partial<VulnListRow> = {}): VulnListRow => ({
  key: "CVE-2026-10037", title: "openssl: memory corruption in the TLS 1.3 handshake", severity: "critical", exploited: true,
  due: day(10), cvss: 9.8, epss: 0.879, epss_percentile: 0.99, packages: ["openssl"], fixed: { kind: "one", version: "3.0.15" },
  open: 3, total: 5, reboot: false, low_confidence: false, advisories: ["DSA-5891-1", "FEDORA-2026-1"], also_covers: ["CVE-2026-10051"],
  assignee: { kind: "one", id: "u-sam", name: "Sam Analyst" }, ...over,
});
const list = (over: Partial<VulnList> = {}): VulnList => ({
  items: [
    row(),
    row({ key: "CVE-2026-10079", title: "glibc: buffer overflow in iconv", severity: "important", exploited: false, due: day(-2), packages: ["glibc", "glibc-common"],
      fixed: { kind: "none" }, open: 5, assignee: { kind: "none" }, advisories: ["FEDORA-2026-2"], also_covers: [] }),
    row({ key: "CVE-2026-10112", due: day(60), fixed: { kind: "several", count: 2 }, assignee: { kind: "several", count: 2 }, cvss: null, epss: null }),
  ],
  total: 3, generated_at: "2026-10-22T10:00:00Z",
  summary: { open_rows: 10, hosts: 5, exploited: 4, with_due: 3, no_fix: 2, unassigned: 6 },
  counts: {
    state: [{ value: "open", count: 10 }, { value: "mitigated", count: 1 }, { value: "accepted_risk", count: 0 }, { value: "false_positive", count: 0 },
      { value: "resolved", count: 2 }, { value: "all", count: 12 }],
    severity: [{ value: "critical", count: 2 }, { value: "important", count: 5 }],
    signal: [{ value: "exploited", count: 4 }, { value: "due30", count: 2 }, { value: "nofix", count: 2 }, { value: "reboot", count: 0 }, { value: "lowconf", count: 1 }],
    package: [{ value: "openssl", count: 2 }],
    group: [{ value: "g1", name: "Web", kind: "manual", count: 2 }],
    assignee: { me: 1, unassigned: 6, people: [{ value: "u-sam", name: "Sam Analyst", count: 1 }] },
  },
  ...over,
});
const render = (data: VulnList, hidden: string[] = []) =>
  renderToStaticMarkup(<VulnListBody list={data} hidden={hidden} selected={new Set()} onSelect={() => undefined} />).replace(/<!-- -->/g, "");

describe("Vulnerabilities list", () => {
  it("asks the API only for what it reads, in its spelling, one page at a time", () => {
    expect(apiQuery(new URLSearchParams("q=ssl&signal=nofix&package=openssl&host=a%2F1&advisory=X-1&offset=50&sort=hosts&dir=asc&bad=1")))
      .toBe("q=ssl&signal=nofix&package=openssl&host=a%2F1&advisory=X-1&dir=asc&offset=50&sort=open&limit=50");
    expect(apiQuery(new URLSearchParams("sort=due"))).toBe("sort=due&limit=50");
    // No sort is the API's priority order.
    expect(apiQuery(new URLSearchParams())).toBe("limit=50");
  });

  it("renders screen 25's columns: the CVE a real link to its page, package and fix, CVSS, EPSS, hosts, due and assignee", () => {
    const html = render(list());
    for (const header of ["Severity", "Advisory", "Package", "CVSS", "EPSS", "Hosts", "Due", "Assignee"]) expect(html).toContain(`>${header}<`);
    expect(html).toContain('href="/vulnerabilities/CVE-2026-10037"');
    // The link's name carries the key for screen readers.
    expect(html).toContain('<span class="sr-only"> (CVE-2026-10037)</span></a>');
    expect(html).toContain("Exploited");
    expect(html).toContain("fixed in 3.0.15");
    expect(html).toContain("no fix yet");
    expect(html).toContain("fixed in 2 versions");
    expect(html).toContain("glibc +1");
    expect(html).toContain("9.8");
    expect(html).toContain("87.9%");
    expect(html).toContain("Sam Analyst");
    expect(html).toContain("2 people");
    expect(html).toContain("Unassigned");
  });

  it("names the hosts bar for screen readers", () => {
    const html = render(list());
    expect(html).toMatch(/role="progressbar"[^>]*aria-label="3 open of 5 hosts"|aria-label="3 open of 5 hosts"[^>]*role="progressbar"/);
    expect(html).toContain('aria-valuetext="3 open of 5 hosts"');
  });

  it("shows the due date amber within 30 days and red when overdue", () => {
    const html = render(list());
    expect(html).toMatch(/class="due due--soon"/);
    expect(html).toMatch(/class="due due--late"/);
    expect(html).toContain("overdue");
    expect(html).toContain("(due within 30 days)");
    // 60 days out: neither.
    expect(html.match(/class="due"/g)?.length).toBe(1);
  });

  it("leaves out hidden columns, never Severity or Advisory", () => {
    const html = render(list(), ["package", "due", "severity", "advisory"]);
    expect(html).not.toContain(">Package<");
    expect(html).not.toContain(">Due<");
    expect(html).toContain(">Severity<");
    expect(html).toContain(">Advisory<");
  });

  it("says the summary line of ruling 6", () => {
    expect(render(list())).toContain("10 open on 5 hosts · 4 known exploited · 3 with a due date · 2 without a fix · 6 unassigned");
  });

  it("offers every filter of screen 25, Host and Advisory only while set", () => {
    const filters = vulnFilters(list(), { host: "agent-1", hostName: "web-01", advisory: "FEDORA-2026-1" });
    expect(filters.map((f) => f.label)).toEqual(["Severity", "State", "Signals", "Package", "Group", "Assignee", "Host", "Advisory"]);
    expect(filters.find((f) => f.param === "host")).toMatchObject({ chipOnly: true, values: [{ value: "agent-1", label: "web-01" }] });
    expect(filters.find((f) => f.param === "advisory")).toMatchObject({ chipOnly: true, values: [{ value: "FEDORA-2026-1", label: "FEDORA-2026-1" }] });
    expect(filters.find((f) => f.param === "state")?.values.map((v) => v.label)).toEqual(["Open", "Mitigated", "Accepted risk", "False positive", "Resolved", "All states"]);
    expect(filters.find((f) => f.param === "signal")?.values.map((v) => v.label))
      .toEqual(["Known exploited", "Due within 30 days", "No fix yet", "Reboot needed", "Lower confidence"]);
    expect(filters.find((f) => f.param === "severity")?.values.map((v) => v.label)).toEqual(["Critical", "Important"]);
    expect(filters.find((f) => f.param === "assignee")?.values.map((v) => v.label)).toEqual(["Me", "Unassigned", "Sam Analyst"]);
    const unset = vulnFilters(list(), { host: null, hostName: undefined, advisory: null });
    expect(unset.filter((f) => f.chipOnly).map((f) => [f.param, f.values.length])).toEqual([["host", 0], ["advisory", 0]]);
  });

  it("sends each ticked row's covering advisories, on the Host chip's host when set (ruling 8)", () => {
    const rows = list().items.slice(0, 2);
    // The second row has no fix: nothing of it can be triaged, so it sends nothing.
    expect(bulkItems(rows, null)).toEqual([{ advisory_id: "DSA-5891-1", open_only: true }, { advisory_id: "FEDORA-2026-1", open_only: true }]);
    // The Host chip names the host; open_only keeps its closed pairs out of reach.
    expect(bulkItems([row(), row({ key: "CVE-2026-10051" })], "agent-1"))
      .toEqual([{ advisory_id: "DSA-5891-1", agent_id: "agent-1", open_only: true }, { advisory_id: "FEDORA-2026-1", agent_id: "agent-1", open_only: true }]);
    // With the Group filter set, the row's counts are the group's, and so is what it changes.
    expect(bulkItems([row()], null, "grp-web")).toEqual([{ advisory_id: "DSA-5891-1", open_only: true, group: "grp-web" }, { advisory_id: "FEDORA-2026-1", open_only: true, group: "grp-web" }]);
  });

  it("sends no version-range (CPE:) advisory, and offers nothing for rows that cannot change", () => {
    expect(bulkItems([row({ advisories: ["CPE:CVE-2026-10037:openssl", "DSA-5891-1"] })], null)).toEqual([{ advisory_id: "DSA-5891-1", open_only: true }]);
    const [fixable, nofix] = list().items;
    if (!fixable || !nofix) throw new Error("fixture");
    const cpe = row({ advisories: ["CPE:CVE-2026-10037:openssl"] });
    // A mixed selection: only the fixable row is counted and confirmed.
    expect(listBulk([fixable, nofix, cpe])).toMatchObject({ changes: 1, rows: [fixable], without: [] });
    // Nothing that can change: no Set state, Assign or Add to case (they would send nothing).
    expect(listBulk([nofix, cpe])).toMatchObject({ changes: 0, rows: [], without: ["state", "assign", "case"] });
  });

  it("says why when nothing selected can be triaged, and only then", () => {
    const session = { principal: { id: "u-me", username: "me", display_name: "Me" }, capabilities: [] } as unknown as Session;
    const bar = (rows: VulnListRow[]) => {
      const bulk = listBulk(rows);
      return renderToStaticMarkup(<SessionContext.Provider value={{ session, demo: false, can: () => true, canEverywhere: () => true }}>
        <BulkBar kind="vulnerabilities" noun="vulnerabilities" count={rows.length} items={() => []} onClear={() => undefined} newCase={() => ({ title: "x" })}
          without={bulk.without} changes={bulk.changes} note={bulk.note} />
      </SessionContext.Provider>);
    };
    const [fixable, nofix] = list().items;
    if (!fixable || !nofix) throw new Error("fixture");
    expect(bar([nofix])).toContain("Nothing selected can be triaged");
    expect(bar([fixable, nofix])).not.toContain("Nothing selected can be triaged");
  });

  it("counts the open hosts a change reaches and names the other CVEs those advisories cover", () => {
    const rows = list().items.slice(0, 2);
    expect(bulkReach(rows)).toEqual({ open: 8, others: ["CVE-2026-10051"] });
    // A CVE ticked itself is not "other".
    expect(bulkReach([row(), row({ key: "CVE-2026-10051", also_covers: ["CVE-2026-10037"] })]).others).toEqual([]);
  });

  it("reads the key from /vulnerabilities/{key}, nothing from other paths", () => {
    expect(vulnKeyOf("/vulnerabilities/CVE-2026-1")).toBe("CVE-2026-1");
    expect(vulnKeyOf("/vulnerabilities/CVE-2026-1/x")).toBeNull();
    expect(vulnKeyOf("/vulnerabilities/%E0")).toBeNull();
    expect(vulnKeyOf("/vulnerabilities/")).toBeNull();
  });
});
