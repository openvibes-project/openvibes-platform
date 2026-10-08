import { describe, expect, it } from "vitest";
import type { Agent, AlarmPage, FindingGroup, Vulnerability } from "../api/types";
import { ATTENTION_KINDS, buildAttention } from "./attention";

const vuln = (advisory_id: string, severity: string) => ({ advisory_id, severity, title: advisory_id, agent_id: "a" }) as unknown as Vulnerability;
const alarm = (id: string, severity: string) => ({ id, severity, message: id, exe: "/bin/x", agent_id: "a", hostname: "h", count: 1 }) as unknown as AlarmPage["items"][number];
const group = (rule_id: string, severity: string) => ({ rule_set_id: "s", rule_id, severity, latest_message: rule_id, triage_counts: { open: 1 } }) as unknown as FindingGroup;

describe("needs attention", () => {
  it("offers the serious kind by default", () => {
    expect(ATTENTION_KINDS).toContain("serious");
  });
  it("ranks one item of each kind and starts each meta with its kind", () => {
    const items = buildAttention({
      alarms: [alarm("al-high", "high"), alarm("al-crit", "critical")],
      exploited: [vuln("kev", "important")],
      serious: [vuln("kev", "important"), vuln("v-high", "important"), vuln("v-crit", "critical")],
      groups: [group("c-high", "high"), group("c-crit", "critical")],
      stale: [{ id: "g1", hostname: "quiet", last_seen_at: null } as unknown as Agent],
    });
    expect(items.map((i) => [i.title, i.meta.split(" · ")[0]])).toEqual([
      ["al-crit", "Alarm"], ["kev", "Vulnerability"], ["v-crit", "Vulnerability"], ["c-crit", "Compliance"],
      ["v-high", "Vulnerability"], ["al-high", "Alarm"], ["c-high", "Compliance"], ["quiet", "Host"],
    ]);
    expect(items.at(-1)?.rank).toBe(5);
  });
});

