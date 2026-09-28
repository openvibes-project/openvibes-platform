// The "Needs attention" list and the greeting, used by the built-in
// Overview dashboard and the Attention tile.
import { useMemo } from "react";

import { useAllPages, useResource } from "../api/client";
import type { Agent, FindingGroup, VulnerabilityPage } from "../api/types";
import { useSession } from "../app/session";
import { plural } from "../ui/format";
import type { IconName } from "../ui/Icon";

export type AttentionItem = { key: string; icon: IconName; to: { kind: string; id: string }; severity: string; title: string; meta: string; rank: number };

export function greeting(now = new Date()) {
  const hour = now.getHours();
  return hour < 5 ? "Good night" : hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";
}

/** The "Needs attention" list: exploited vulnerabilities, open critical and
 *  high findings, and hosts that stopped reporting, most urgent first. */
export function useAttention(include: readonly string[], limit: number): { items: AttentionItem[]; loading: boolean } {
  const { can } = useSession();
  const want = (kind: string) => include.includes(kind);
  const groups = useAllPages<FindingGroup>(want("findings") && can("findings.read") ? "/api/v1/findings/groups" : null);
  const exploited = useResource<VulnerabilityPage>(want("exploited") && can("vulnerabilities.read") ? "/api/v1/vulnerabilities?exploited=true" : null);
  const stale = useAllPages<Agent>(want("stale") && can("agents.read") ? "/api/v1/agents?state=stale" : null);

  const items = useMemo(() => {
    const items: AttentionItem[] = [];
    const byAdvisory = new Map<string, { title: string; severity: string; hosts: number }>();
    for (const item of exploited.data?.items ?? []) {
      const entry = byAdvisory.get(item.advisory_id) ?? { title: item.title, severity: item.severity, hosts: 0 };
      entry.hosts += 1;
      byAdvisory.set(item.advisory_id, entry);
    }
    for (const [id, entry] of byAdvisory) {
      items.push({ key: `a${id}`, icon: "flame", to: { kind: "advisory", id }, severity: entry.severity, title: entry.title, meta: `Known exploited · ${plural(entry.hosts, "host")}`, rank: 0 - entry.hosts / 1000 });
    }
    for (const group of groups.data ?? []) {
      if (group.triage_counts.open === 0 || (group.severity !== "critical" && group.severity !== "high")) continue;
      items.push({ key: `f${group.rule_set_id}/${group.rule_id}`, icon: "findings", to: { kind: "finding", id: `${group.rule_set_id}/${group.rule_id}` }, severity: group.severity, title: group.latest_message, meta: `${group.rule_id} · ${plural(group.triage_counts.open, "host")} open`, rank: (group.severity === "critical" ? 1 : 3) - group.triage_counts.open / 1000 });
    }
    const silent = [...(stale.data ?? [])].sort((a, b) => (a.last_seen_at ?? "").localeCompare(b.last_seen_at ?? "")).slice(0, 6);
    for (const agent of silent) {
      items.push({ key: `g${agent.id}`, icon: "agents", to: { kind: "agent", id: agent.id }, severity: "stale", title: agent.hostname ?? agent.id, meta: "Stopped reporting", rank: 2 });
    }
    return items.sort((a, b) => a.rank - b.rank);
  }, [exploited.data, groups.data, stale.data]);
  return { items: items.slice(0, limit), loading: groups.loading || exploited.loading || stale.loading };
}
