// What the Software list and a package's page read in the demo: each
// reachable host's packages (context.ts hostPackages), the open advisories
// that name them, the services that run from them (serviceData.ts) and the
// change log's last weeks of package events. Deterministic, so the same
// fleet answers the same way after a reload.
import type { DemoContext } from "./context";
import { isActive } from "./hostGroups";
import { hostServices } from "./routes/assets";
import { serviceHosts } from "./serviceData";

export type SoftwareVersion = { manager: string; epoch: number; version: string; release: string; arch: string };
export type SoftwareHost = { id: string; hostname: string | null; reportedAt: string; versions: SoftwareVersion[] };
export type SoftwareAdvisory = {
  id: string; title: string; severity: string; cves: string[]; cvss: number | null; epss: number | null; exploited: boolean; url: string;
  /** The fixed version, null when nothing fixes it. */
  fixed: string | null;
  /** Hosts with it open, and of those the ones an update fixes. */
  hosts: Set<string>; fixable: Set<string>;
  /** The installed version per host. */
  installed: Map<string, string>;
};
export type SoftwareChange = { at: number; agent: string; name: string; change: "appeared" | "went_away"; version: string };

const DAY = 86_400_000;
const SEVERITIES = ["critical", "important", "moderate", "low", "unrated"];
export const severityRank = (severity: string) => (SEVERITIES.includes(severity) ? SEVERITIES.indexOf(severity) : SEVERITIES.length - 1);

/** The version as the server writes it: `epoch:version-release`. */
export const fullVersion = (v: { epoch: number; version: string; release: string }) => `${v.epoch > 0 ? `${v.epoch}:` : ""}${v.version}${v.release ? `-${v.release}` : ""}`;

/** The numbers of a version compared as numbers, so 10.1 is after 9.9. */
export function natural(a: string, b: string): number {
  const x = a.split(/(\d+)/);
  const y = b.split(/(\d+)/);
  for (let i = 0; i < Math.min(x.length, y.length); i += 1) {
    const [p = "", q = ""] = [x[i], y[i]];
    const d = i % 2 === 1 ? Number(p) - Number(q) : p < q ? -1 : p > q ? 1 : 0;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}
export const byVersion = (a: SoftwareVersion, b: SoftwareVersion) => a.epoch - b.epoch || natural(a.version, b.version) || natural(a.release, b.release);

/** Reachable, non-revoked hosts per package name, one entry per host. */
export function softwareHosts(ctx: DemoContext): Map<string, SoftwareHost[]> {
  const rows = new Map<string, SoftwareHost[]>();
  for (const agent of ctx.hosts().filter((a) => isActive(ctx.facts(a)))) {
    const reportedAt = hostServices(ctx.data, agent.id).reported_at;
    for (const p of ctx.hostPackages(agent.id)) {
      const version = { manager: p.manager, epoch: p.epoch, version: p.version, release: p.release, arch: p.arch };
      rows.set(p.name, [...(rows.get(p.name) ?? []), { id: agent.id, hostname: agent.hostname ?? null, reportedAt, versions: [version] }]);
    }
  }
  return rows;
}

/** The open advisories (80% confidence or more, not waived) per package name over the hosts in reach. */
export function softwareAdvisories(ctx: DemoContext, reach: Set<string>): Map<string, Map<string, SoftwareAdvisory>> {
  const out = new Map<string, Map<string, SoftwareAdvisory>>();
  for (const v of ctx.data.vulnerabilities) {
    if (v.fixed_at != null || v.confidence < 80 || v.triage_state !== "open" || !reach.has(v.agent_id)) continue;
    for (const p of v.packages as { name: string; installed: string; fixed?: string | null }[]) {
      const advisories = out.get(p.name) ?? new Map<string, SoftwareAdvisory>();
      const a = advisories.get(v.advisory_id) ?? {
        id: v.advisory_id, title: v.title, severity: v.severity, cves: v.cves, cvss: v.cvss ?? null, epss: v.epss ?? null, exploited: v.exploited || v.kev || v.euvd, url: v.url,
        fixed: p.fixed ?? null, hosts: new Set<string>(), fixable: new Set<string>(), installed: new Map<string, string>(),
      };
      a.hosts.add(v.agent_id);
      a.installed.set(v.agent_id, p.installed);
      if (p.fixed != null && !v.reboot_needed) a.fixable.add(v.agent_id);
      advisories.set(v.advisory_id, a);
      out.set(p.name, advisories);
    }
  }
  return out;
}

/** The units that run from each package, by the hosts that run them. */
export function softwareUnits(ctx: DemoContext): Map<string, Map<string, Set<string>>> {
  const out = new Map<string, Map<string, Set<string>>>();
  for (const [unit, hosts] of serviceHosts(ctx)) {
    for (const h of hosts) {
      if (!h.package) continue;
      const units = out.get(h.package.name) ?? new Map<string, Set<string>>();
      units.set(unit, (units.get(unit) ?? new Set()).add(h.id));
      out.set(h.package.name, units);
    }
  }
  return out;
}

/** The change log for packages: a role's first host installs, updates (the old version going, the new appearing) or removes one. */
export function softwareChanges(ctx: DemoContext): SoftwareChange[] {
  const now = Date.parse(ctx.iso());
  const first = (role: string) => ctx.hosts().find((a) => (a.hostname ?? "").startsWith(`${role}-`));
  const events: [string, string, SoftwareChange["change"], number, string][] = [
    ["web", "nginx", "went_away", 2, "1.24.0-1"], ["web", "nginx", "appeared", 2, "1.24.0-2"], ["db", "redis", "appeared", 1, "7.2.4-1"],
    ["api", "openssl", "went_away", 4, "3.2.2-2.fc44"], ["api", "openssl", "appeared", 4, "3.2.2-3.fc44"], ["vpn", "wireguard-tools", "appeared", 6, "1.0.20-1"],
    ["files", "samba", "went_away", 3, "4.19.5-1"], ["web", "nginx", "appeared", 40, "1.24.0-1"],
  ];
  const out: SoftwareChange[] = [];
  for (const [role, name, change, days, version] of events) {
    const agent = first(role);
    if (agent) out.push({ at: now - days * DAY, agent: agent.id, name, change, version });
  }
  return out;
}
