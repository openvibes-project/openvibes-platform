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

/** What the list is built from; each part is empty when its kind is off.
 *  `seriousMore`: the server cut the serious vulnerabilities short, so host counts are lower bounds. */
export type AttentionInput = { alarms: Alarm[]; exploited: Vulnerability[]; serious: Vulnerability[]; seriousMore?: boolean; groups: FindingGroup[]; stale: Agent[] };

const SERIOUS_ADVISORIES = 20;

/** Bands: critical alarm -1, exploited 0, critical of any kind 1, high of any kind 3, medium alarm 4,
 *  stale 5. Within a band: more hosts first, then kind order, then title; a count never changes the band. */
export function buildAttention({ alarms, exploited, serious, seriousMore = false, groups, stale }: AttentionInput): AttentionItem[] {
  const items: (AttentionItem & { size: number; order: number })[] = [];
  const add = (order: number, size: number, item: AttentionItem) => items.push({ ...item, size, order });
  const byAdvisory = (list: Vulnerability[]) => {
    const map = new Map<string, { title: string; severity: string; hosts: number }>();
    for (const item of list) {
      const entry = map.get(item.advisory_id) ?? { title: item.title, severity: item.severity, hosts: 0 };
      entry.hosts += 1;
      map.set(item.advisory_id, entry);
    }
    return map;
  };
  for (const [id, entry] of byAdvisory(exploited)) {
    add(1, entry.hosts, { key: `a${id}`, icon: "flame", to: { kind: "advisory", id }, severity: entry.severity, title: entry.title, meta: `Vulnerability · known exploited · ${plural(entry.hosts, "host")}`, rank: 0 });
  }
  // All returned rows are grouped first, then the 20 advisories on most hosts are kept.
  const advisories = [...byAdvisory(serious)].sort(([, a], [, b]) => b.hosts - a.hosts).slice(0, SERIOUS_ADVISORIES);
  for (const [id, entry] of advisories) {
    add(2, entry.hosts, { key: `v${id}`, icon: "vulnerabilities", to: { kind: "advisory", id }, severity: entry.severity, title: entry.title, meta: `Vulnerability · ${seriousMore ? `${entry.hosts}+ hosts` : plural(entry.hosts, "host")}`, rank: entry.severity === "critical" ? 1 : 3 });
  }
  const alarmRank: Record<string, number> = { critical: -1, high: 3, medium: 4 };
  const seen = new Set<string>();
  for (const alarm of alarms) {
    if (seen.has(alarm.id)) continue;
    seen.add(alarm.id);
    const rank = alarmRank[alarm.severity];
    if (rank === undefined) continue;
    const program = alarm.exe.split("/").pop() ?? alarm.exe;
    add(0, alarm.count, { key: `m${alarm.id}`, icon: "alarm", to: { kind: "alarm", id: alarm.id }, severity: alarm.severity, title: alarm.message, meta: `Alarm · ${alarm.hostname ?? alarm.agent_id} · ${program}${alarm.count > 1 ? ` · ${alarm.count}×` : ""}`, rank });
  }
  for (const group of groups) {
    if (group.triage_counts.open === 0 || (group.severity !== "critical" && group.severity !== "high")) continue;
    add(3, group.triage_counts.open, { key: `f${group.rule_set_id}/${group.rule_id}`, icon: "findings", to: { kind: "finding", id: `${group.rule_set_id}/${group.rule_id}` }, severity: group.severity, title: group.latest_message, meta: `Compliance · ${group.rule_id} · ${plural(group.triage_counts.open, "host")} open`, rank: group.severity === "critical" ? 1 : 3 });
  }
  const silent = [...stale].sort((a, b) => (a.last_seen_at ?? "").localeCompare(b.last_seen_at ?? "")).slice(0, 6);
  for (const agent of silent) {
    add(4, 0, { key: `g${agent.id}`, icon: "agents", to: { kind: "agent", id: agent.id }, severity: "stale", title: agent.hostname ?? agent.id, meta: "Host · stopped reporting", rank: 5 });
  }
  return items.sort((a, b) => a.rank - b.rank || b.size - a.size || a.order - b.order || a.title.localeCompare(b.title));
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
  const critical = useResource<VulnerabilityPage>(want("serious") && vulns ? "/api/v1/vulnerabilities?severity=critical&exploited=false" : null);
  const important = useResource<VulnerabilityPage>(want("serious") && vulns ? "/api/v1/vulnerabilities?severity=important&exploited=false" : null);
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
    serious: [...(critical.data?.items ?? []), ...(important.data?.items ?? [])],
    seriousMore: !!(critical.data?.more_available || important.data?.more_available),
    groups: groups.data ?? [],
    stale: stale.data ?? [],
  }), [alarms.data, criticalAlarms.data, exploited.data, critical.data, important.data, groups.data, stale.data]);
  return { items: items.slice(0, limit), loading: groups.loading || exploited.loading || critical.loading || important.loading || stale.loading || alarms.loading || criticalAlarms.loading };
}
