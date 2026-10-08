// The "Needs attention" list and the greeting, used by the built-in
// Overview dashboard and the Attention tile.
import { useMemo } from "react";

import { useAllPages, useResource } from "../api/client";
import type { Agent, AlarmPage, FindingGroup, Vulnerability, VulnerabilityPage } from "../api/types";
import { useSession } from "../app/session";
import { plural } from "../ui/format";
import type { IconName } from "../ui/Icon";

/** What "Needs attention" can include, in the settings' order. */
export const ATTENTION_KINDS = ["alarms", "exploited", "serious", "compliance", "stale"] as const;

type Alarm = AlarmPage["items"][number];
export type AttentionItem = { key: string; icon: IconName; to: { kind: string; id: string }; severity: string; title: string; meta: string; rank: number };

export function greeting(now = new Date()) {
  const hour = now.getHours();
  return hour < 5 ? "Good night" : hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
}

/** What the list is built from; each part is empty when its kind is off. */
export type AttentionInput = { alarms: Alarm[]; exploited: Vulnerability[]; serious: Vulnerability[]; groups: FindingGroup[]; stale: Agent[] };

/** Rank: critical alarm -1, exploited 0, critical of any kind 1, high of any kind 3, stale 5. */
export function buildAttention({ alarms, exploited, serious, groups, stale }: AttentionInput): AttentionItem[] {
  const items: AttentionItem[] = [];
  const byAdvisory = (list: Vulnerability[]) => {
    const map = new Map<string, { title: string; severity: string; hosts: number }>();
    for (const item of list) {
      const entry = map.get(item.advisory_id) ?? { title: item.title, severity: item.severity, hosts: 0 };
      entry.hosts += 1;
      map.set(item.advisory_id, entry);
    }
    return map;
  };
  const known = byAdvisory(exploited);
  for (const [id, entry] of known) {
    items.push({ key: `a${id}`, icon: "flame", to: { kind: "advisory", id }, severity: entry.severity, title: entry.title, meta: `Vulnerability · known exploited · ${plural(entry.hosts, "host")}`, rank: 0 - entry.hosts / 1000 });
  }
  for (const [id, entry] of byAdvisory(serious)) {
    if (known.has(id)) continue;
    const critical = entry.severity === "critical";
    items.push({ key: `v${id}`, icon: "vulnerabilities", to: { kind: "advisory", id }, severity: entry.severity, title: entry.title, meta: `Vulnerability · ${plural(entry.hosts, "host")}`, rank: (critical ? 1 : 3) - entry.hosts / 1000 });
  }
  const alarmRank: Record<string, number> = { critical: -1, high: 3 - 1 / 1000, medium: 4 };
  const seen = new Set<string>();
  for (const alarm of alarms) {
    if (seen.has(alarm.id)) continue;
    seen.add(alarm.id);
    const rank = alarmRank[alarm.severity];
    if (rank === undefined) continue;
    const program = alarm.exe.split("/").pop() ?? alarm.exe;
    items.push({ key: `m${alarm.id}`, icon: "alarm", to: { kind: "alarm", id: alarm.id }, severity: alarm.severity, title: alarm.message, meta: `Alarm · ${alarm.hostname ?? alarm.agent_id} · ${program}${alarm.count > 1 ? ` · ${alarm.count}×` : ""}`, rank });
  }
  for (const group of groups) {
    if (group.triage_counts.open === 0 || (group.severity !== "critical" && group.severity !== "high")) continue;
    items.push({ key: `f${group.rule_set_id}/${group.rule_id}`, icon: "findings", to: { kind: "finding", id: `${group.rule_set_id}/${group.rule_id}` }, severity: group.severity, title: group.latest_message, meta: `Compliance · ${group.rule_id} · ${plural(group.triage_counts.open, "host")} open`, rank: (group.severity === "critical" ? 1 : 3) - group.triage_counts.open / 1000 });
  }
  const silent = [...stale].sort((a, b) => (a.last_seen_at ?? "").localeCompare(b.last_seen_at ?? "")).slice(0, 6);
  for (const agent of silent) {
    items.push({ key: `g${agent.id}`, icon: "agents", to: { kind: "agent", id: agent.id }, severity: "stale", title: agent.hostname ?? agent.id, meta: "Host · stopped reporting", rank: 5 });
  }
  return items.sort((a, b) => a.rank - b.rank);
}

/** The "Needs attention" list: alarms, exploited and serious vulnerabilities,
 *  open critical and high compliance findings, and hosts that stopped
 *  reporting, most urgent first. */
export function useAttention(include: readonly string[], limit: number): { items: AttentionItem[]; loading: boolean } {
  const { can } = useSession();
  const want = (kind: string) => include.includes(kind);
  const groups = useAllPages<FindingGroup>(want("compliance") && can("compliance.read") ? "/api/v1/compliance/groups" : null);
  const vulns = want("exploited") || want("serious") ? can("vulnerabilities.read") : false;
  const exploited = useResource<VulnerabilityPage>(want("exploited") && vulns ? "/api/v1/vulnerabilities?exploited=true" : null);
  const critical = useResource<VulnerabilityPage>(want("serious") && vulns ? "/api/v1/vulnerabilities?severity=critical" : null);
  const important = useResource<VulnerabilityPage>(want("serious") && vulns ? "/api/v1/vulnerabilities?severity=important" : null);
  const stale = useAllPages<Agent>(want("stale") && can("agents.read") ? "/api/v1/agents?state=stale" : null);
  // Newest first by last_seen: repeating medium alarms could push an older
  // critical one off one page, so critical ones are fetched on their own.
  // (Alarms closed by a suppression are hidden unless suppressed=true.)
  const alarmsOn = want("alarms") && can("alarms.read");
  const alarms = useResource<AlarmPage>(alarmsOn ? "/api/v1/alarms?state=active&limit=20" : null);
  const criticalAlarms = useResource<AlarmPage>(alarmsOn ? "/api/v1/alarms?state=active&severity=critical&limit=20" : null);

  const items = useMemo(() => buildAttention({
    alarms: [...(criticalAlarms.data?.items ?? []), ...(alarms.data?.items ?? [])],
    exploited: exploited.data?.items ?? [],
    // The vulnerability list has no limit parameter: 20 of each severity.
    serious: [...(critical.data?.items ?? []).slice(0, 20), ...(important.data?.items ?? []).slice(0, 20)],
    groups: groups.data ?? [],
    stale: stale.data ?? [],
  }), [alarms.data, criticalAlarms.data, exploited.data, critical.data, important.data, groups.data, stale.data]);
  return { items: items.slice(0, limit), loading: groups.loading || exploited.loading || critical.loading || important.loading || stale.loading || alarms.loading || criticalAlarms.loading };
}
