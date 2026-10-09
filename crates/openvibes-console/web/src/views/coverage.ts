// Coverage page logic (spec 2026-10-09-attack-coverage-design.md §4): the
// matrix columns and the filtered rule list, from GET /api/v1/rules/coverage.
import type { AttackPair, CoverageRule, Tactic } from "../api/types";

export type Cell = { technique: string; name: string; rules: number; sub: boolean };
export type Column = { key: string; title: string; tactics: string[]; rules: number; cells: Cell[] };

/** The kill-chain phases in order; a phase the server does not know goes last. */
export const PHASES = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation", "Command and Control", "Actions on Objectives", "Unmapped phase"];

export function selectRules(rules: readonly CoverageRule[], params: URLSearchParams): CoverageRule[] {
  const kind = params.get("kind");
  const drafts = params.get("drafts") === "true";
  const technique = params.get("technique");
  const tactic = params.get("tactic");
  const unmapped = params.get("unmapped") === "true";
  const q = (params.get("q") ?? "").toLowerCase();
  return rules.filter((r) =>
    (drafts || !r.draft)
    && (!kind || r.kind === kind)
    && (!unmapped || r.attack.length === 0)
    && (!technique || r.attack.some((p) => p.technique === technique || p.technique?.startsWith(`${technique}.`)))
    && (!tactic || r.attack.some((p) => p.tactic === tactic))
    && (!q || [r.title, r.rule_id, r.rule_set_id, ...r.attack.flatMap((p) => [p.technique ?? "", p.technique_name ?? ""])].some((s) => s.toLowerCase().includes(q))));
}

/** Matrix columns: one per tactic, or one per kill-chain phase. Cells are
 * the covered techniques with how many rules claim them under that column;
 * a sub-technique sorts right after its parent. */
export function columns(tactics: readonly Tactic[], rules: readonly CoverageRule[], byPhase: boolean): Column[] {
  const groups: { key: string; title: string; tactics: string[] }[] = byPhase
    ? PHASES.map((phase) => ({ key: phase, title: phase, tactics: tactics.filter((t) => t.phase === phase).map((t) => t.id) }))
      .filter((g) => g.tactics.length > 0 || g.key !== "Unmapped phase")
    : tactics.map((t) => ({ key: t.id, title: t.name, tactics: [t.id] }));
  return groups.map((g) => {
    const cells = new Map<string, Cell>();
    const covering = new Set<string>();
    for (const rule of rules) {
      const id = `${rule.rule_set_id}/${rule.rule_id}`;
      const seen = new Set<string>();
      for (const pair of rule.attack.filter((p: AttackPair) => g.tactics.includes(p.tactic))) {
        covering.add(id);
        const key = pair.technique ?? "";
        if (!key || seen.has(key)) continue;
        seen.add(key);
        const cell = cells.get(key) ?? { technique: key, name: pair.technique_name ?? key, rules: 0, sub: key.includes(".") };
        cell.rules += 1;
        cells.set(key, cell);
      }
    }
    return { ...g, rules: covering.size, cells: [...cells.values()].sort((a, b) => a.technique.localeCompare(b.technique)) };
  });
}
