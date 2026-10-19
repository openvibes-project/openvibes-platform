import { describe, expect, it } from "vitest";

import type { HostRuleSetAssignments, RuleSet, RuleSetAssignment } from "../../api/types";
import { addGroupBlocked, factsNote, factsUnavailable, hardeningParts, readsRules, ruleSetRows, runsOn, shortName, sourceDetail } from "./ruleAssignment";

const L1 = "hardening-linux-l1";
const L2 = "hardening-linux-l2";
const l1: RuleSetAssignment = { rule_set_id: L1, default_enabled: true, published: true, hosts_on: 162, hosts_off: 24, groups: [{ asset_group_id: "g-prod", name: "Production", enabled: false }] };
const l2: RuleSetAssignment = { rule_set_id: L2, default_enabled: false, published: false, hosts_on: 0, hosts_off: 186, groups: [] };
const baseline: RuleSet = { rule_set_id: "baseline", retired: false, trusted_keys: 1, current_signer_removed: false, current_version: 14, current_issuer_key_id: "ops-2026", current_expires_at_ms: 0 };

describe("the Rule sets list", () => {
  it("lists published sets and assignable ones, an unpublished set too", () => {
    expect(ruleSetRows([baseline], [l1, l2]).map((r) => [r.rule_set_id, Boolean(r.set), Boolean(r.assignment)])).toEqual([
      ["baseline", true, false], [L1, false, true], [L2, false, true],
    ]);
  });
  it("says where each set runs: the default, then how many groups differ", () => {
    expect(runsOn("baseline", undefined)).toEqual({ text: "All hosts", more: null });
    expect(runsOn("baseline-alarms", undefined)).toEqual({ text: "Linux", more: null });
    expect(runsOn("site", undefined)).toEqual({ text: "Hosts that trust its key", more: null });
    expect(runsOn(L1, l1)).toEqual({ text: "Linux", more: "· 1 group off" });
    expect(runsOn(L2, l2)).toEqual({ text: "Off", more: null });
    const three = [{ asset_group_id: "a", name: "Lab", enabled: true }, { asset_group_id: "b", name: "Web", enabled: true }, { asset_group_id: "c", name: "Db", enabled: false }];
    expect(runsOn(L2, { ...l2, groups: three })).toEqual({ text: "Off", more: "· 2 groups on" });
  });
  it("names the source with its checks and level", () => {
    expect(sourceDetail(L1, 43)).toBe("(43 checks, Level 1)");
    expect(sourceDetail(L2, null)).toBe("(Level 2: stricter, may affect services)");
    expect(sourceDetail(L1, 0)).toBe("(Level 1)");
    expect(sourceDetail("site", null)).toBe("");
  });
  it("explains why a group cannot be added", () => {
    expect(addGroupBlocked(0, 0)).toBe("No asset groups yet: create one under Settings › Host groups.");
    expect(addGroupBlocked(2, 0)).toBe("Every asset group is listed.");
    expect(addGroupBlocked(2, 1)).toBeNull();
  });
});

describe("the host's Hardening line", () => {
  const set = (rule_set_id: string, enabled: boolean, extra: Partial<HostRuleSetAssignments["items"][number]> = {}) =>
    ({ rule_set_id, enabled, source: "default", group: null, published: true, ...extra });
  const parts = (items: HostRuleSetAssignments["items"], rule_sets: { id: string; version?: number | null; state?: string | null }[], at: string | null = "2026-10-15T10:00:00Z") =>
    hardeningParts({ items, hardening_facts: null }, { rule_sets, rule_sets_at: at });

  it("names the group that switched a set off", () => {
    expect(parts([set(L1, false, { source: "group", group: "Production" }), set(L2, false, { published: false })], [{ id: L1, state: "not_assigned" }])).toEqual([
      { name: "L1", on: false, group: "Production", note: null },
      { name: "L2", on: false, group: null, note: null },
    ]);
  });
  it("an on set that is not published waits; a host in two on groups shows the one the platform names", () => {
    expect(parts([set(L2, true, { source: "group", group: "alpha", published: false })], [])[0]).toEqual({ name: "L2", on: true, group: "alpha", note: "waits until published" });
  });
  it("is pending until the agent's report agrees", () => {
    expect(parts([set(L1, false, { source: "group", group: "Lab" })], [{ id: L1, version: 4 }])[0]?.note).toBe("pending");
    expect(parts([set(L1, true)], [{ id: L1, state: "not_assigned" }])[0]?.note).toBe("pending");
    expect(parts([set(L1, true)], [])[0]?.note).toBe("pending");
    expect(parts([set(L1, true)], [{ id: L1, version: 4 }])[0]?.note).toBeNull();
    expect(parts([set(L1, false)], [])[0]?.note).toBeNull();
    expect(parts([set(L1, true)], [], null)[0]?.note).toBeNull();
  });
  it("short names and facts", () => {
    expect(shortName(L1)).toBe("L1");
    expect(shortName("site")).toBe("site");
    expect([null, undefined, "ok", "not_found", "invalid_data"].map(factsUnavailable)).toEqual([false, false, false, true, true]);
  });
  it("says for how long the root-facts helper has not reported, since enrollment, or that its facts were invalid", () => {
    const now = Date.parse("2026-10-15T12:00:00Z");
    const tail = " (openvibes-agent-facts.timer), so checks that read root-only files show as unavailable, not failed.";
    expect(factsNote("not_found", "2026-10-12T11:00:00Z", now)).toBe(`The agent's root-facts helper has not reported for 3 days${tail}`);
    expect(factsNote("not_found", "2026-10-15T09:00:00Z", now)).toBe(`The agent's root-facts helper has not reported for 1 day${tail}`);
    expect(factsNote("not_found", null, now)).toBe(`The agent's root-facts helper has not reported since enrollment${tail}`);
    expect(factsNote("invalid_data", "2026-10-12T11:00:00Z", now)).toBe(`The agent's root-facts helper sent invalid hardening facts${tail}`);
  });
});

describe("who reads the rule sets", () => {
  it("rules.read", () => {
    const holding = (...held: string[]) => (p: string) => held.includes(p);
    expect([readsRules(holding("rules.read")), readsRules(holding("rules.publish")), readsRules(holding("hosts.read"))]).toEqual([true, false, false]);
  });
});
