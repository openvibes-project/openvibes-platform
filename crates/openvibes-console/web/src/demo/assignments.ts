// The demo's rule-set assignment: the real API's routes, JSON and status codes
// (crates/openvibes-console/src/rule_assignment.rs,
// docs/components/rule-set-assignment.md), in memory and, in a browser, in
// localStorage. Hosts, tags and asset groups come from the rest of the demo,
// so the Access view's groups are the same ones.
import type { Agent, HostRuleSetAssignments, RuleSetAssignment, RuleSetAssignments } from "../api/types";
import type { DemoData } from "./data";

type Result = { status: number; body?: unknown };
type Saved = { defaults: Record<string, boolean>; overrides: Record<string, Record<string, boolean>> };
type Persistence = { load: () => unknown; save: (state: unknown) => void } | undefined;

const SEED: Saved = {
  defaults: { "hardening-linux-l1": true, "hardening-linux-l2": false },
  overrides: { "hardening-linux-l1": { "grp-prod": false }, "hardening-linux-l2": {} },
};
const problem = (status: number, code: string, title: string): Result => ({ status, body: { status, code, title } });
const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name);

export function createAssignmentStore(data: DemoData, audit: (setId: string) => void, persistence: Persistence) {
  const loaded = persistence?.load() as Saved | null | undefined;
  const state: Saved = loaded?.defaults && loaded.overrides ? loaded : structuredClone(SEED);
  const save = () => persistence?.save(state);
  const ids = () => Object.keys(state.defaults).sort((a, b) => a.localeCompare(b));
  // A deleted group's overrides are gone, as the database's cascade does.
  const groups = () => data.access.asset_groups;
  // Stale hosts count: in the real DB stale is derived from last-seen, so their status stays active.
  const linux = () => data.agents.filter((a) => a.status !== "revoked" && a.status !== "imported" && a.os_id);
  const member = (agent: Agent, selectors: readonly string[]) =>
    selectors.length > 0 && selectors.every((s) => (data.tags.get(agent.id) ?? []).some((t) => `${t.key}=${t.value}` === s));
  const published = (id: string) => data.ruleSets.some((s) => s.rule_set_id === id && !s.retired);
  const overridden = (id: string) => groups().filter((g) => g.asset_group_id in (state.overrides[id] ?? {})).sort(byName);
  const decide = (id: string, agent: Agent) => {
    const mine = overridden(id).filter((g) => member(agent, g.selectors));
    const on = mine.filter((g) => state.overrides[id]?.[g.asset_group_id]);
    const deciding = on.length ? on : mine;
    return { enabled: mine.length ? on.length > 0 : state.defaults[id] ?? false, group: deciding[0]?.name ?? null };
  };
  const view = (id: string): RuleSetAssignment => {
    const hosts = linux();
    const on = hosts.filter((a) => decide(id, a).enabled).length;
    return {
      rule_set_id: id, default_enabled: state.defaults[id] ?? false, published: published(id), hosts_on: on, hosts_off: hosts.length - on,
      groups: overridden(id).map((g) => ({ asset_group_id: g.asset_group_id, name: g.name, enabled: state.overrides[id]?.[g.asset_group_id] ?? false })),
    };
  };
  const setGroup = (id: string, groupId: string, enabled: boolean | null): Result => {
    if (!(id in state.defaults)) return problem(404, "rule_set_not_assignable", "Rule set is not assignable");
    if (!groups().some((g) => g.asset_group_id === groupId)) return problem(404, "asset_group_not_found", "Asset group not found");
    const { [groupId]: current = null, ...rest } = state.overrides[id] ?? {};
    if (current !== enabled) {
      state.overrides[id] = enabled === null ? rest : { ...rest, [groupId]: enabled };
      audit(id);
      save();
    }
    return { status: 200, body: view(id) };
  };
  return {
    list: (): RuleSetAssignments => ({
      items: ids().map(view),
      asset_groups: [...groups()].sort(byName).map((g) => ({ asset_group_id: g.asset_group_id, name: g.name, selectors: g.selectors, hosts: linux().filter((a) => member(a, g.selectors)).length })),
    }),
    setDefault(id: string, body: Record<string, unknown>): Result {
      if (!(id in state.defaults)) return problem(404, "rule_set_not_assignable", "Rule set is not assignable");
      if (typeof body.default_enabled !== "boolean") return problem(400, "invalid_request", "The request body is not valid");
      if (state.defaults[id] !== body.default_enabled) { state.defaults[id] = body.default_enabled; audit(id); save(); }
      return { status: 200, body: view(id) };
    },
    setGroup(id: string, groupId: string, body: Record<string, unknown>): Result {
      return typeof body.enabled === "boolean" ? setGroup(id, groupId, body.enabled) : problem(400, "invalid_request", "The request body is not valid");
    },
    clearGroup: (id: string, groupId: string): Result => setGroup(id, groupId, null),
    host(agent: Agent): HostRuleSetAssignments {
      const n = Number(agent.id.slice(-5));
      const facts = !agent.os_id || agent.status === "imported" ? null : n % 17 === 0 ? "not_found" : "ok";
      return {
        items: ids().map((id) => {
          const decided = decide(id, agent);
          const fromGroup = overridden(id).some((g) => member(agent, g.selectors));
          return { rule_set_id: id, enabled: decided.enabled, source: fromGroup ? "group" : "default", group: fromGroup ? decided.group : null, published: published(id) };
        }),
        hardening_facts: facts,
        // Missing facts: last usable 3 days ago, or never since enrollment (agent-00034).
        hardening_facts_ok_at: facts === "ok" ? agent.rule_sets_at ?? null : n === 34 ? null : new Date(Date.now() - 3 * 86_400_000 - 3_600_000).toISOString(),
      };
    },
  };
}
