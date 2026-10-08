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
      serious: [vuln("v-high", "important"), vuln("v-crit", "critical")],
      groups: [group("c-high", "high"), group("c-crit", "critical")],
      stale: [{ id: "g1", hostname: "quiet", last_seen_at: null } as unknown as Agent],
    });
    expect(items.map((i) => [i.title, i.meta.split(" · ")[0]])).toEqual([
      ["al-crit", "Alarm"], ["kev", "Vulnerability"], ["v-crit", "Vulnerability"], ["c-crit", "Compliance"],
      ["al-high", "Alarm"], ["v-high", "Vulnerability"], ["c-high", "Compliance"], ["quiet", "Host"],
    ]);
    expect(items.at(-1)?.rank).toBe(5);
  });
  it("groups every returned row before keeping 20 advisories, and says when the page was cut", () => {
    const rows = [...Array.from({ length: 30 }, (_, i) => vuln(`adv-${i}`, "critical")), ...Array.from({ length: 5 }, () => vuln("adv-0", "critical"))];
    const items = buildAttention({ alarms: [], exploited: [vuln("kev", "critical")], serious: rows, seriousMore: true, groups: [], stale: [] });
    expect(items).toHaveLength(21);
    expect(items.map((i) => i.title).slice(0, 2)).toEqual(["kev", "adv-0"]);
    expect(items[1]?.meta).toBe("Vulnerability · 6+ hosts");
    expect(items[0]?.meta).toContain("known exploited");
  });
  it("never lets a host count move an item out of its band", () => {
    const many = (n: number, advisory: string, severity: string) => Array.from({ length: n }, () => vuln(advisory, severity));
    const items = buildAttention({
      alarms: [alarm("al-crit", "critical")],
      exploited: [],
      serious: [...many(5000, "v-high", "important"), ...many(1, "v-crit", "critical")],
      groups: [{ ...group("c-high", "high"), triage_counts: { open: 5000 } } as FindingGroup, group("c-crit", "critical")],
      stale: [],
    });
    expect(items.map((i) => i.title)).toEqual(["al-crit", "v-crit", "c-crit", "v-high", "c-high"]);
  });
});
