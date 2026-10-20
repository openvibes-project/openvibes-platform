// Assets: packages (v1), open ports and running services (v2), and software across the fleet.
import type { Vulnerability } from "../../api/types";
import type { DemoContext } from "../context";
import { json, page, problem, severityRank } from "../http";

export function registerAssetRoutes(ctx: DemoContext) {
  const { data, agentById, hosts, hostPackages, vulnerabilities, route } = ctx;
  route("GET", "/api/v1/agents/{id}/packages", "hosts.read", ({ id = "" }, query) => {
    if (!agentById(id)) return problem(404, "not_found", "Agent not found");
    const q = (query.get("q") ?? "").toLowerCase();
    const fixable = query.get("fixable") === "true";
    return json(page(hostPackages(id).filter((p) => p.name.toLowerCase().includes(q) && (!fixable || p.fixable_vulnerable)), query));
  });
  const fleet = () => {
    const rows = new Map<string, { manager: string; name: string; hosts: Set<string>; versions: Set<string>; fixable: Set<string> }>();
    for (const agent of hosts()) {
      for (const p of hostPackages(agent.id)) {
        const key = `${p.manager}/${p.name}`;
        const row = rows.get(key) ?? { manager: p.manager, name: p.name, hosts: new Set(), versions: new Set(), fixable: new Set() };
        row.hosts.add(agent.id);
        row.versions.add(`${p.version}-${p.release}`);
        if (p.fixable_vulnerable) row.fixable.add(agent.id);
        rows.set(key, row);
      }
    }
    return [...rows.values()].sort((a, b) => a.name.localeCompare(b.name));
  };
  // Open advisories naming a package, grouped by advisory, on visible hosts.
  const packageAdvisories = (name: string) => {
    const byAdvisory = new Map<string, { item: Vulnerability; hosts: Set<string>; fixed: string | null }>();
    for (const item of vulnerabilities()) {
      const named = Array.isArray(item.packages) ? (item.packages as { name: string; fixed?: string | null }[]).find((p) => p.name === name) : undefined;
      if (!named) continue;
      const row = byAdvisory.get(item.advisory_id) ?? { item, hosts: new Set<string>(), fixed: named.fixed ?? null };
      row.hosts.add(item.agent_id);
      byAdvisory.set(item.advisory_id, row);
    }
    return [...byAdvisory.values()]
      .map(({ item, hosts: set, fixed }) => ({
        advisory_id: item.advisory_id, severity: item.severity, title: item.title, url: item.url, cves: item.cves, hosts: set.size,
        fixed_in: fixed, exploited: item.exploited, epss: item.epss ?? null, cvss: item.cvss ?? null,
      }))
      .sort((a, b) => Number(b.exploited) - Number(a.exploited) || (b.epss ?? 0) - (a.epss ?? 0) || (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9));
  };
  route("GET", "/api/v1/agents/{id}/services", "hosts.read", ({ id = "" }) => {
    if (!agentById(id)) return problem(404, "agent_not_found", "Agent not found");
    return json(hostServices(data, id));
  });
  route("GET", "/api/v1/ports", "hosts.read", (_, query) => {
    const rows = new Map<string, { protocol: string; port: number; hosts: number; exposed_hosts: number; services: Set<string> }>();
    for (const agent of hosts()) {
      for (const l of hostServices(data, agent.id).listeners) {
        const row = rows.get(`${l.protocol}/${l.port}`) ?? { protocol: l.protocol, port: l.port, hosts: 0, exposed_hosts: 0, services: new Set() };
        row.hosts += 1;
        if (l.exposed) row.exposed_hosts += 1;
        row.services.add(l.service);
        rows.set(`${l.protocol}/${l.port}`, row);
      }
    }
    const exposed = query.get("exposed") === "true";
    return json([...rows.values()].filter((r) => !exposed || r.exposed_hosts > 0).sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol)).map((r) => ({ ...r, services: [...r.services].sort((a, b) => a.localeCompare(b)).slice(0, 8) })));
  });
  route("GET", "/api/v1/services", "hosts.read", () => {
    const counts = new Map<string, number>();
    for (const agent of hosts()) for (const s of hostServices(data, agent.id).services) counts.set(s.unit, (counts.get(s.unit) ?? 0) + 1);
    return json([...counts].sort(([a], [b]) => a.localeCompare(b)).map(([unit, hosts]) => ({ unit, hosts })));
  });
  route("GET", "/api/v1/ports/{protocol}/{port}", "hosts.read", ({ protocol = "", port = "" }, query) => {
    const found = hosts().flatMap((agent) => hostServices(data, agent.id).listeners
      .filter((l) => l.protocol === protocol && String(l.port) === port)
      .map((l) => ({ agent_id: agent.id, hostname: agent.hostname ?? null, address: l.address, exposed: l.exposed, service: l.service, program: l.program, last_seen_at: agent.last_seen_at ?? null })));
    if (found.length === 0) return problem(404, "port_not_found", "No host listens on this port");
    const { items, next_cursor } = page(found.sort((a, b) => (a.hostname ?? "").localeCompare(b.hostname ?? "")), query);
    return json({ protocol, port: Number(port), hosts: items, next_cursor });
  });
  route("GET", "/api/v1/services/{unit}", "hosts.read", ({ unit = "" }, query) => {
    const name = decodeURIComponent(unit);
    const found = hosts().flatMap((agent) => hostServices(data, agent.id).services
      .filter((s) => s.unit === name)
      .map((s) => ({ agent_id: agent.id, hostname: agent.hostname ?? null, programs: s.programs, processes: s.processes, run_as: s.run_as, last_seen_at: agent.last_seen_at ?? null })));
    if (found.length === 0) return problem(404, "service_not_found", "No host runs this service");
    const { items, next_cursor } = page(found.sort((a, b) => (a.hostname ?? "").localeCompare(b.hostname ?? "")), query);
    return json({ unit: name, hosts: items, next_cursor });
  });
  route("GET", "/api/v1/software", "hosts.read", (_, query) => {
    const q = (query.get("q") ?? "").toLowerCase();
    const fixable = query.get("fixable") === "true";
    const multiple = query.get("multiple_versions") === "true";
    const items = fleet().filter((row) => row.name.toLowerCase().includes(q) && (!fixable || row.fixable.size > 0) && (!multiple || row.versions.size > 1))
      .map((row) => {
        const advisories = packageAdvisories(row.name);
        const worst = advisories.map((a) => a.severity).sort((a, b) => (severityRank[a] ?? 9) - (severityRank[b] ?? 9))[0] ?? null;
        return {
          manager: row.manager, name: row.name, hosts: row.hosts.size, versions: row.versions.size, fixable_vulnerable_hosts: row.fixable.size,
          advisories: advisories.length, no_fix_advisories: advisories.filter((a) => a.fixed_in == null).length, worst_severity: worst, exploited: advisories.some((a) => a.exploited),
        };
      });
    return json(page(items, query));
  });
  route("GET", "/api/v1/software/{manager}/{name}", "hosts.read", ({ manager = "", name = "" }, query) => {
    const found = hosts().flatMap((agent) => hostPackages(agent.id).filter((p) => p.manager === manager && p.name === decodeURIComponent(name)).map((p) => ({ agent, p })));
    if (found.length === 0) return problem(404, "not_found", "No visible host has it");
    const versions = new Map<string, { epoch: number; version: string; release: string; arch: string; hosts: number; fixable_vulnerable_hosts: number; advisories: number }>();
    for (const { p } of found) {
      const key = `${p.version}-${p.release}.${p.arch}`;
      const v = versions.get(key) ?? { epoch: p.epoch, version: p.version, release: p.release, arch: p.arch, hosts: 0, fixable_vulnerable_hosts: 0, advisories: 0 };
      v.hosts += 1;
      if (p.fixable_vulnerable) { v.fixable_vulnerable_hosts += 1; v.advisories = packageAdvisories(p.name).length; }
      versions.set(key, v);
    }
    const { items, next_cursor } = page(found.map(({ agent, p }) => ({ agent_id: agent.id, hostname: agent.hostname ?? null, version: `${p.version}-${p.release}`, arch: p.arch, last_seen_at: agent.last_seen_at ?? null, fixable_vulnerable: p.fixable_vulnerable })), query);
    return json({ manager, name: decodeURIComponent(name), versions: [...versions.values()], advisories: packageAdvisories(decodeURIComponent(name)), hosts: items, next_cursor });
  });
}

// Assets v2: open ports and running services, from the host's role.
const PORTS: Record<string, [number, string, string][]> = {
  web: [[443, "nginx.service", "nginx"], [80, "nginx.service", "nginx"]], proxy: [[443, "haproxy.service", "haproxy"]], api: [[8080, "api.service", "node"]],
  db: [[5432, "postgresql.service", "postgres"]], cache: [[6379, "redis.service", "redis-server"]], mail: [[25, "postfix.service", "master"]],
};
export function hostServices(data: DemoContext["data"], agentId: string) {
  const role = (data.agents.find((a) => a.id === agentId)?.hostname ?? "").split("-")[0] ?? "";
  const own = PORTS[role] ?? [];
  const listeners = [
    ...own.map(([port, service, program]) => ({ protocol: "tcp", address: "0.0.0.0", port, exposed: true, service, program })),
    { protocol: "tcp", address: "0.0.0.0", port: 22, exposed: true, service: "sshd.service", program: "sshd" },
    { protocol: "udp", address: "127.0.0.53", port: 53, exposed: false, service: "systemd-resolved.service", program: "systemd-resolve" },
  ].sort((a, b) => Number(b.exposed) - Number(a.exposed) || a.port - b.port);
  const units = new Map(listeners.map((l) => [l.service, l.program]));
  units.set("chronyd.service", "chronyd");
  const services = [...units].map(([unit, program]) => ({ unit, programs: [program], processes: unit === "nginx.service" ? 3 : 1, run_as: "root" })).sort((a, b) => a.unit.localeCompare(b.unit));
  // The mail hosts' last report was refused (over 512 KiB): the tab says so.
  const refused = role === "mail" ? { refused: "too_large", refused_at: new Date(Date.now() - 5 * 60_000).toISOString() } : { refused: null, refused_at: null };
  // The build hosts run more than a report carries: their lists were cut.
  return { reported_at: new Date(Date.now() - 20 * 60_000).toISOString(), owners: "partial", truncated: role === "build", ...refused, listeners, services };
}
