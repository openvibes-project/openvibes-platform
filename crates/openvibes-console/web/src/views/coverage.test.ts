import { describe, expect, it } from "vitest";

import type { CoverageRule, Tactic } from "../api/types";
import { columns, selectRules } from "./coverage";

const tactics: Tactic[] = [
  { id: "TA0001", name: "Initial Access", phase: "Delivery" },
  { id: "TA0002", name: "Execution", phase: "Exploitation" },
  { id: "TA0003", name: "Persistence", phase: "Installation" },
];
const rule = (id: string, kind: string, attack: [string, string | null][], draft = false): CoverageRule => ({
  rule_set_id: draft ? "site" : "baseline", rule_id: id, title: `Rule ${id}`, kind, severity: "high", draft,
  attack: attack.map(([tactic, technique]) => ({ tactic, technique, technique_name: technique ? `Name ${technique}` : null, known: true })),
});
const rules = [
  rule("redis", "snapshot", [["TA0001", "T1190"]]),
  rule("shell", "process_event", [["TA0002", "T1059.004"], ["TA0001", "T1190"]]),
  rule("nc", "process_event", [["TA0002", "T1059"]]),
  rule("draft", "snapshot", [["TA0003", "T1505.003"]], true),
  rule("bare", "snapshot", []),
];

describe("coverage", () => {
  it("drafts are hidden unless asked for; filters combine", () => {
    expect(selectRules(rules, new URLSearchParams()).map((r) => r.rule_id)).toEqual(["redis", "shell", "nc", "bare"]);
    expect(selectRules(rules, new URLSearchParams("drafts=true"))).toHaveLength(5);
    expect(selectRules(rules, new URLSearchParams("kind=process_event")).map((r) => r.rule_id)).toEqual(["shell", "nc"]);
    expect(selectRules(rules, new URLSearchParams("unmapped=true")).map((r) => r.rule_id)).toEqual(["bare"]);
  });

  it("a technique filter includes its sub-techniques", () => {
    expect(selectRules(rules, new URLSearchParams("technique=T1059")).map((r) => r.rule_id)).toEqual(["shell", "nc"]);
    expect(selectRules(rules, new URLSearchParams("technique=T1059.004")).map((r) => r.rule_id)).toEqual(["shell"]);
  });

  it("tactic columns count rules and techniques; empty tactics stay as gaps", () => {
    const cols = columns(tactics, selectRules(rules, new URLSearchParams()), false);
    expect(cols.map((c) => [c.key, c.rules])).toEqual([["TA0001", 2], ["TA0002", 2], ["TA0003", 0]]);
    expect(cols[0]?.cells).toEqual([{ technique: "T1190", name: "Name T1190", rules: 2, sub: false }]);
    expect(cols[1]?.cells.map((c) => [c.technique, c.sub])).toEqual([["T1059", false], ["T1059.004", true]]);
  });

  it("the kill-chain view groups tactics into phases", () => {
    const cols = columns(tactics, rules, true);
    expect(cols.map((c) => c.key)).toEqual(["Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation", "Command and Control", "Actions on Objectives"]);
    expect(cols.find((c) => c.key === "Installation")?.rules).toBe(1);
  });
});
