// Rule-set assignment in the console (spec 2026-10-14 §6; approved screens in
// docs/specs/rule-set-assignment-ui/approved.md): the parts without React.
import type { Agent, HostRuleSetAssignments, Permission, RuleSet, RuleSetAssignment } from "../api/types";
import { type Access, grantsAny } from "../app/session";

/** Where the project's sets that are not assignable run. */
const FIXED: Record<string, string> = { baseline: "All hosts", "baseline-alarms": "Linux" };
/** The panel's Source detail per assignable set. */
const LEVEL: Record<string, string> = { "hardening-linux-l1": "Level 1", "hardening-linux-l2": "Level 2: stricter, may affect services" };

type RuleSetRow = { rule_set_id: string; set: RuleSet | undefined; assignment: RuleSetAssignment | undefined };

/** Published sets and assignable ones: an assignable set is listed before it is published. */
export function ruleSetRows(sets: readonly RuleSet[], assignments: readonly RuleSetAssignment[]): RuleSetRow[] {
  const ids = [...new Set([...sets.map((s) => s.rule_set_id), ...assignments.map((a) => a.rule_set_id)])].sort((a, b) => a.localeCompare(b));
  return ids.map((id) => ({ rule_set_id: id, set: sets.find((s) => s.rule_set_id === id), assignment: assignments.find((a) => a.rule_set_id === id) }));
}

/** The list's Runs on cell: the default (Linux, or Off), then how many groups differ from it. */
export function runsOn(id: string, assignment: RuleSetAssignment | undefined): { text: string; more: string | null } {
  if (!assignment) return { text: FIXED[id] ?? "Hosts that trust its key", more: null };
  const on = assignment.default_enabled;
  const differ = assignment.groups.filter((g) => g.enabled !== on).length;
  return { text: on ? "Linux" : "Off", more: differ ? `· ${differ} ${differ === 1 ? "group" : "groups"} ${on ? "off" : "on"}` : null };
}

/** The panel's Source detail, "(43 checks, Level 1)"; no count when unknown or zero. */
export function sourceDetail(id: string, checks: number | null): string {
  const parts = [checks ? `${checks} checks` : null, LEVEL[id] ?? null].filter(Boolean);
  return parts.length ? `(${parts.join(", ")})` : "";
}

/** hardening-linux-l1 → L1. */
export function shortName(id: string): string {
  const level = /-l(\d+)$/.exec(id)?.[1];
  return level ? `L${level}` : id;
}

export type HardeningPart = { name: string; on: boolean; group: string | null; note: "waits until published" | "pending" | null };

/** The host's Hardening line, one part per assignable set: the platform's
 * decision, the group that decided it, and whether the agent has caught up. */
export function hardeningParts(host: HostRuleSetAssignments, agent: Pick<Agent, "rule_sets" | "rule_sets_at">): HardeningPart[] {
  return host.items.map((set) => {
    const reported = agent.rule_sets.find((r) => r.id === set.rule_set_id);
    const running = reported !== undefined && reported.state !== "not_assigned";
    // ponytail: "pending" = the agent's latest report disagrees; no switch time is stored, so an agent too old to know the project sets stays "pending" for an on set until it is updated. Store the change time if that confuses.
    const note = set.enabled && !set.published ? "waits until published"
      : agent.rule_sets_at != null && set.enabled !== running ? "pending" : null;
    return { name: shortName(set.rule_set_id), on: set.enabled, group: set.group ?? null, note };
  });
}

/** The latest report says the root-facts helper's hardening facts could not be used. */
export const factsUnavailable = (outcome: string | null | undefined): boolean => outcome != null && outcome !== "ok";

const FACTS_TAIL = " (openvibes-agent-facts.timer), so checks that read root-only files show as unavailable, not failed.";

/** Why hardening checks show as unavailable (approved screen 8; rulings G1, G4): for
 * how many days (at least 1) since a stored report last had usable facts, "since
 * enrollment" when none did, or that the facts sent were invalid. */
export function factsNote(outcome: string, okAt: string | null | undefined, now = Date.now()): string {
  if (outcome === "invalid_data") return `The agent's root-facts helper sent invalid hardening facts${FACTS_TAIL}`;
  if (!okAt) return `The agent's root-facts helper has not reported since enrollment${FACTS_TAIL}`;
  const days = Math.max(1, Math.floor((now - Date.parse(okAt)) / 86_400_000));
  return `The agent's root-facts helper has not reported for ${days} ${days === 1 ? "day" : "days"}${FACTS_TAIL}`;
}

/** Who reads the rule sets, their switches, history and coverage: `rules.read` or `rules.upload`, globally. */
export const RULE_READERS: readonly Access[] = [{ permission: "rules.read", global: true }, { permission: "rules.upload", global: true }];

export const readsRules = (can: (permission: Permission, global?: boolean) => boolean): boolean => grantsAny(can, RULE_READERS);

/** Why "+ Add group" is disabled, or null when a group can be added. */
export function addGroupBlocked(groups: number, free: number): string | null {
  if (groups === 0) return "No asset groups yet: create one under Settings › Access.";
  return free === 0 ? "Every asset group is listed." : null;
}
