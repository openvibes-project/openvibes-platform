// Markup only (vitest runs in node); clicks, keys and toasts are in the e2e (Task 8).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { AssignableGroup, RuleSetAssignment } from "../../api/types";
import { WhereItRuns } from "./WhereItRuns";

const prod: AssignableGroup = { asset_group_id: "g-prod", name: "Production", kind: "manual", summary: "24 hosts picked by hand", hosts: 24 };
const lab: AssignableGroup = { asset_group_id: "g-lab", name: "Lab", kind: "rule", summary: "Hosts where hostname matches lab-*", hosts: 31 };
const l1: RuleSetAssignment = { rule_set_id: "hardening-linux-l1", default_enabled: true, published: true, hosts_on: 162, hosts_off: 24, groups: [{ asset_group_id: "g-prod", name: "Production", enabled: false }] };
const l2: RuleSetAssignment = { rule_set_id: "hardening-linux-l2", default_enabled: false, published: false, hosts_on: 0, hosts_off: 186, groups: [] };
const html = (assignment: RuleSetAssignment, groups: AssignableGroup[], canChange = true) =>
  renderToStaticMarkup(<WhereItRuns assignment={assignment} groups={groups} canChange={canChange} />);

describe("Where it runs", () => {
  it("a published set: the default, the counts, the overrides with tags and hosts, the explanation", () => {
    const out = html(l1, [prod, lab]);
    expect(out).toContain('<h3 class="section-title">Where it runs</h3>');
    expect(out).toContain("On for Linux hosts by default");
    expect(out).toContain("Runs on <b>162</b> Linux hosts · off on <b>24</b>.");
    expect(out).toContain('aria-label="Group overrides"');
    expect(out).toContain('<span class="subtle">24 hosts picked by hand</span>');
    expect(out).toContain('aria-label="Runs for Production"');
    expect(out).toContain('aria-label="Remove Production"');
    expect(out).toContain("+ Add group");
    expect(out).toContain("A host runs it when any of its groups has it on; otherwise when the default is on. Hosts follow on their next scan.");
  });
  it("an unpublished set says it is not available yet, and that no group differs", () => {
    const out = html(l2, [prod, lab]);
    expect(out).toContain("<b>Not available yet.</b>");
    expect(out).toContain("This platform has no L2 set yet: it comes with a later rules package. Switches you set now are kept and apply when it is published.");
    expect(out).toContain("No group differs from the default.");
    expect(out).not.toContain("Runs on");
    expect(out).not.toContain("Group overrides");
  });
  it("without rules.assignment.write the switches are read-only and nothing can be added or removed", () => {
    const out = html(l1, [prod, lab], false);
    expect(out.match(/role="switch"[^>]*disabled=""/g)).toHaveLength(2);
    expect(out).not.toContain("+ Add group");
    expect(out).not.toContain("Remove Production");
  });
  it("with no asset groups, Add group is disabled and says why", () => {
    const out = html(l2, []);
    expect(out).toMatch(/disabled="">\+ Add group/);
    expect(out).toContain("No asset groups yet: create one under Settings › Host groups.");
  });
  it("a very long group name stays on one line, with the full name on hover", () => {
    const long = "g".repeat(200);
    const out = html({ ...l1, groups: [{ asset_group_id: "g-long", name: long, enabled: false }] }, [{ ...prod, asset_group_id: "g-long", name: long }]);
    expect(out).toContain(`<div class="truncate" style="max-width:220px" title="${long}">${long}</div>`);
  });
});
