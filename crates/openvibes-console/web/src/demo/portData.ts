// What the Ports list and a port's page read in the demo: each reachable
// host's listeners from its role (routes/assets.ts hostServices), and the
// change log's last week of listener events. Deterministic, so the same fleet
// answers the same way after a reload.
import type { DemoContext } from "./context";
import { inGroup, isActive } from "./hostGroups";
import { hostServices } from "./routes/assets";

export type PortHost = { id: string; hostname: string | null; bound: string[]; exposed: boolean; service: string | null; program: string | null; reportedAt: string };
export type PortChange = { at: number; agent: string; key: string; change: "appeared" | "went_away" | "exposed" | "local" };
const DAY = 86_400_000;

/** Reachable, non-revoked hosts per port key, one entry per host however many addresses it binds. */
export function portHosts(ctx: DemoContext): Map<string, PortHost[]> {
  const rows = new Map<string, PortHost[]>();
  for (const agent of ctx.hosts().filter((a) => isActive(ctx.facts(a)))) {
    const report = hostServices(ctx.data, agent.id);
    const byKey = new Map<string, PortHost>();
    for (const l of report.listeners) {
      const key = `${l.protocol}/${l.port}`;
      const seen = byKey.get(key);
      if (seen) {
        seen.bound.push(l.address);
        seen.exposed ||= l.exposed;
        seen.service ??= l.service ?? null;
        seen.program ??= l.program ?? null;
      } else {
        byKey.set(key, { id: agent.id, hostname: agent.hostname ?? null, bound: [l.address], exposed: l.exposed, service: l.service ?? null, program: l.program ?? null, reportedAt: report.reported_at });
      }
    }
    for (const [key, host] of byKey) rows.set(key, [...(rows.get(key) ?? []), host]);
  }
  return rows;
}

/**
 * The change log for listeners, in reach: the first host of a role starts a
 * port this week, one web host stopped port 80, one database host became
 * reachable from the network two days ago, and one database host started 5432 ten days ago.
 */
export function portChanges(ctx: DemoContext): PortChange[] {
  const now = Date.parse(ctx.iso());
  const first = (role: string) => ctx.hosts().find((a) => (a.hostname ?? "").startsWith(`${role}-`));
  const events: [string, string, string, PortChange["change"], number][] = [
    ["vpn", "udp/1194", "", "appeared", 1], ["files", "tcp/8888", "", "appeared", 2], ["ws", "tcp/3389", "", "appeared", 3],
    ["web", "tcp/443", "", "appeared", 5], ["api", "tcp/80", "", "went_away", 1], ["db", "tcp/5432", "", "exposed", 2], ["db", "tcp/5432", "", "appeared", 10],
  ];
  const out: PortChange[] = [];
  for (const [role, key, , change, days] of events) {
    const agent = first(role);
    if (agent) out.push({ at: now - days * DAY, agent: agent.id, key, change });
  }
  return out;
}

/** Groups of kind automatic or rule that hold a host, by id. */
export function groupIdsOf(ctx: DemoContext, agentId: string, kinds: readonly string[] = ["automatic", "rule"]): string[] {
  const agent = ctx.data.agents.find((a) => a.id === agentId);
  const f = agent ? ctx.facts(agent) : undefined;
  return f && isActive(f) ? ctx.data.access.host_groups.filter((g) => kinds.includes(g.kind) && inGroup(f, g)).map((g) => g.asset_group_id) : [];
}
