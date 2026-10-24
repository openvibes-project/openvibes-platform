// The Compliance list (approved screen 27), as markup (no DOM library in
// vitest; see ui/controls.test.tsx). Filters, saved views, columns and the
// bulk bar in a browser: e2e/demo/check-list.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/compliance", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { CheckList, CheckListRow } from "../../api/types";
import { BulkBar } from "../../panels/triage/BulkBar";
import { withSession } from "../../test-session";
import { CheckListBody, apiQuery, bulkItems, checkFilters, checkKeyOf, listBulk } from "./Findings";

const row = (over: Partial<CheckListRow> = {}): CheckListRow => ({
  rule_set_id: "hardening-linux-l1", rule_id: "harden.ssh.permit_root_login", title: "SSH allows root to log in with a password", severity: "high",
  area: "SSH", failing: 5, passing: 6, open: 3, mitigated: 2, accepted_risk: 0, false_positive: 0, since: "2026-09-10T08:00:00Z",
  assignee: { kind: "one", id: "u-sam", name: "Sam Analyst" }, ...over,
});
const list = (over: Partial<CheckList> = {}): CheckList => ({
  items: [
    row(),
    row({ rule_set_id: "baseline", rule_id: "port.redis.exposed", title: "Redis exposed to the network", severity: null, area: "Network exposure",
      failing: 1, passing: 10, open: 1, mitigated: 0, accepted_risk: 1, false_positive: 1, assignee: { kind: "none" } }),
    row({ rule_id: "harden.net.ip_forward", failing: 0, passing: 7, open: 0, mitigated: 0, since: null, assignee: { kind: "several", count: 2 } }),
  ],
  total: 3, generated_at: "2026-10-24T10:00:00Z",
  summary: { failing_checks: 10, hosts: 11, critical: 3, unassigned: 7, rule_sets: [{ value: "baseline", count: 6 }, { value: "hardening-linux-l1", count: 4 }] },
  counts: {
    state: [{ value: "open", count: 10 }, { value: "mitigated", count: 1 }, { value: "accepted_risk", count: 2 }, { value: "false_positive", count: 0 },
      { value: "passing", count: 8 }, { value: "all", count: 12 }],
    severity: [{ value: "critical", count: 3 }, { value: "high", count: 5 }, { value: "info", count: 0 }],
    rule_set: [{ value: "baseline", count: 6 }, { value: "hardening-linux-l1", count: 4 }],
    area: [{ value: "Network exposure", count: 4 }, { value: "SSH", count: 2 }],
    group: [{ value: "g1", name: "Web", kind: "manual", count: 2 }],
    assignee: { me: 1, unassigned: 7, people: [{ value: "u-sam", name: "Sam Analyst", count: 1 }] },
  },
  ...over,
});
const render = (data: CheckList, hidden: string[] = []) =>
  renderToStaticMarkup(<CheckListBody list={data} hidden={hidden} selected={new Set()} onSelect={() => undefined} />).replace(/<!-- -->/g, "");

describe("Compliance list", () => {
  it("asks the API only for what it reads, in its spelling, one page at a time", () => {
    expect(apiQuery(new URLSearchParams("q=ssh&rule_set=baseline&area=SSH&host=a%2F1&offset=50&sort=check&dir=asc&window=all&bad=1")))
      .toBe("q=ssh&rule_set=baseline&area=SSH&host=a%2F1&dir=asc&offset=50&sort=title&limit=50");
    expect(apiQuery(new URLSearchParams("sort=failing"))).toBe("sort=failing&limit=50");
    // A column the API can't sort by sends no sort: the API's default (severity).
    expect(apiQuery(new URLSearchParams("sort=hosts"))).toBe("limit=50");
  });

  it("renders screen 27's columns: the check a real link to its page, with its rule ID and rule set under it", () => {
    const html = render(list());
    for (const header of ["Severity", "Check", "Area", "Failing", "Hosts", "Since", "Assignee"]) expect(html).toContain(`>${header}<`);
    expect(html).toContain('href="/compliance/hardening-linux-l1/harden.ssh.permit_root_login"');
    // The link's name carries the rule ID for screen readers.
    expect(html).toContain('SSH allows root to log in with a password<span class="sr-only"> (harden.ssh.permit_root_login)</span></a>');
    expect(html).toContain("harden.ssh.permit_root_login</span> · hardening-linux-l1");
    expect(html).toContain("Network exposure");
    expect(html).toContain("Sam Analyst");
    expect(html).toContain("2 people");
    expect(html).toContain("Unassigned");
  });

  it('says "n of m" failing: failing hosts of failing and passing ones', () => {
    const html = render(list());
    expect(html).toContain("<b>5</b> <span class=\"subtle\">of 11</span>");
    expect(html).toContain("<b>0</b> <span class=\"subtle\">of 7</span>");
  });

  it("draws the hosts bar with words under it, named for screen readers", () => {
    const html = render(list());
    expect(html).toContain("3 open · 2 mitigated · 6 pass");
    // Only the states that hold a host are named; open always.
    expect(html).toContain("1 open · 1 accepted · 1 false positive · 10 pass");
    expect(html).toContain("0 open · 7 pass");
    expect(html).toMatch(/role="progressbar"[^>]*aria-label="Hosts: 3 open · 2 mitigated · 6 pass"/);
    expect(html).toContain('aria-valuetext="3 open · 2 mitigated · 6 pass"');
  });

  it("leaves out hidden columns, never Severity or Check", () => {
    const html = render(list(), ["area", "since", "severity", "check"]);
    expect(html).not.toContain(">Area<");
    expect(html).not.toContain(">Since<");
    expect(html).toContain(">Severity<");
    expect(html).toContain(">Check<");
  });

  it("says the summary line of ruling 7, with a count per rule set", () => {
    expect(render(list())).toContain("10 checks failing on 11 hosts · 3 critical · 7 unassigned · baseline 6, hardening-linux-l1 4");
  });

  it("offers every filter of screen 27, Host only while set", () => {
    const filters = checkFilters(list(), { host: "agent-1", hostName: "web-01" });
    expect(filters.map((f) => f.label)).toEqual(["Severity", "State", "Rule set", "Area", "Group", "Assignee", "Host"]);
    expect(filters.find((f) => f.param === "host")).toMatchObject({ chipOnly: true, values: [{ value: "agent-1", label: "web-01" }] });
    expect(filters.find((f) => f.param === "state")?.values.map((v) => v.label)).toEqual(["Open", "Mitigated", "Accepted risk", "False positive", "Passing", "All states"]);
    expect(filters.find((f) => f.param === "severity")?.values.map((v) => v.label)).toEqual(["Critical", "High", "Info"]);
    expect(filters.find((f) => f.param === "rule_set")?.values.map((v) => v.label)).toEqual(["baseline", "hardening-linux-l1"]);
    expect(filters.find((f) => f.param === "area")?.values.map((v) => [v.label, v.count])).toEqual([["Network exposure", 4], ["SSH", 2]]);
    expect(filters.find((f) => f.param === "assignee")?.values.map((v) => v.label)).toEqual(["Me", "Unassigned", "Sam Analyst"]);
    expect(checkFilters(list(), { host: null, hostName: undefined }).find((f) => f.param === "host")?.values).toEqual([]);
  });

  it("sends each ticked failing check, open pairs only, on the Host chip's host when set (ruling 10)", () => {
    const [ssh, redis, passing] = list().items;
    if (!ssh || !redis || !passing) throw new Error("fixture");
    expect(bulkItems([ssh, redis, passing], null)).toEqual([
      { rule_set_id: "hardening-linux-l1", rule_id: "harden.ssh.permit_root_login", open_only: true },
      { rule_set_id: "baseline", rule_id: "port.redis.exposed", open_only: true },
    ]);
    expect(bulkItems([ssh], "agent-1")).toEqual([{ rule_set_id: "hardening-linux-l1", rule_id: "harden.ssh.permit_root_login", agent_id: "agent-1", open_only: true }]);
    // With the Group filter set, the row's counts are the group's, and so is what it changes.
    expect(bulkItems([ssh], null, "grp-web")).toEqual([{ rule_set_id: "hardening-linux-l1", rule_id: "harden.ssh.permit_root_login", open_only: true, group: "grp-web" }]);
  });

  it("counts a passing-only check for nothing, and offers nothing for a selection of only those", () => {
    const [ssh, , passing] = list().items;
    if (!ssh || !passing) throw new Error("fixture");
    expect(listBulk([ssh, passing])).toMatchObject({ changes: 1, open: 3, without: [] });
    expect(listBulk([passing])).toMatchObject({ changes: 0, open: 0, without: ["state", "assign", "case"] });
    // Failing, but no failing host open (State: Mitigated): nothing to set or assign; Add to case still adds them.
    const mitigated = row({ open: 0, mitigated: 5 });
    expect(listBulk([mitigated, passing])).toMatchObject({ changes: 1, open: 0, without: ["state", "assign"] });
  });

  it("says why when nothing selected can change, and only then", () => {
    const bar = (rows: CheckListRow[]) => {
      const bulk = listBulk(rows);
      return renderToStaticMarkup(withSession(
        <BulkBar kind="compliance" noun="checks" count={rows.length} items={() => []} onClear={() => undefined} newCase={() => ({ title: "x" })}
          without={bulk.without} changes={bulk.changes} note={bulk.note} />,
      ));
    };
    const [ssh, , passing] = list().items;
    if (!ssh || !passing) throw new Error("fixture");
    expect(bar([passing])).toContain("Nothing selected can be triaged");
    expect(bar([ssh, passing])).not.toContain("Nothing selected can be triaged");
  });

  it("reads the rule set and rule from /compliance/{set}/{rule}, nothing from other paths", () => {
    expect(checkKeyOf("/compliance/baseline/port.ssh.exposed")).toEqual(["baseline", "port.ssh.exposed"]);
    expect(checkKeyOf("/compliance/a%2Fb/c%20d")).toEqual(["a/b", "c d"]);
    expect(checkKeyOf("/compliance/baseline")).toBeNull();
    expect(checkKeyOf("/compliance/baseline/x/y")).toBeNull();
    expect(checkKeyOf("/compliance/%E0/x")).toBeNull();
    expect(checkKeyOf("/compliance//x")).toBeNull();
  });
});
