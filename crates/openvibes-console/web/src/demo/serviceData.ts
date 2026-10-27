// What the Services list and a service's page read in the demo: each
// reachable host's units from its role (routes/assets.ts hostServices), the
// packages that match them by name, and the change log's last weeks of
// service events. Deterministic, so the same fleet answers the same way
// after a reload.
import type { DemoContext } from "./context";
import { isActive } from "./hostGroups";
import { hostServices } from "./routes/assets";
import { candidates } from "./serviceNames";

export type ServiceHost = {
  id: string; hostname: string | null; programs: string[]; processes: number; runAs: string | null; reportedAt: string;
  ports: { protocol: string; port: number; exposed: boolean }[]; package: { name: string; version: string } | null; ownersPartial: boolean;
};
export type ServiceChange = { at: number; agent: string; unit: string; change: "appeared" | "went_away" };
const DAY = 86_400_000;
const PRIVILEGED = new Set(["root", "0", "system", "localsystem", "nt authority\\system"]);
export const privileged = (user: string | null | undefined) => user != null && PRIVILEGED.has(user.toLowerCase());

/** Reachable, non-revoked hosts per unit, one entry per host. */
export function serviceHosts(ctx: DemoContext): Map<string, ServiceHost[]> {
  const rows = new Map<string, ServiceHost[]>();
  for (const agent of ctx.hosts().filter((a) => isActive(ctx.facts(a)))) {
    const report = hostServices(ctx.data, agent.id);
    const installed = ctx.hostPackages(agent.id);
    for (const s of report.services) {
      const wanted = candidates(s.unit);
      const match = installed.filter((p) => wanted.includes(p.name.toLowerCase())).sort((a, b) => a.name.localeCompare(b.name))[0];
      const ports = report.listeners.filter((l) => l.service === s.unit).map((l) => ({ protocol: l.protocol, port: l.port, exposed: l.exposed }));
      const unique = [...new Map(ports.map((p) => [`${p.protocol}/${p.port}`, p])).values()];
      const host: ServiceHost = {
        id: agent.id, hostname: agent.hostname ?? null, programs: s.programs, processes: s.processes, runAs: s.run_as, reportedAt: report.reported_at, ports: unique,
        package: match ? { name: match.name, version: `${match.version}-${match.release}` } : null, ownersPartial: report.owners === "partial",
      };
      rows.set(s.unit, [...(rows.get(s.unit) ?? []), host]);
    }
  }
  return rows;
}

/** The change log for services: a role's first host starts or stops a unit this week or earlier. */
export function serviceChanges(ctx: DemoContext): ServiceChange[] {
  const now = Date.parse(ctx.iso());
  const first = (role: string) => ctx.hosts().find((a) => (a.hostname ?? "").startsWith(`${role}-`));
  const events: [string, string, ServiceChange["change"], number][] = [
    ["vpn", "openvpn-server@server.service", "appeared", 1], ["files", "smb.service", "appeared", 3], ["ws", "xrdp.service", "appeared", 2],
    ["web", "nginx.service", "appeared", 5], ["api", "api.service", "went_away", 1], ["db", "postgresql.service", "appeared", 10],
  ];
  const out: ServiceChange[] = [];
  for (const [role, unit, change, days] of events) {
    const agent = first(role);
    if (agent) out.push({ at: now - days * DAY, agent: agent.id, unit, change });
  }
  return out;
}
