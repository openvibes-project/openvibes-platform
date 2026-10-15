// Vulnerabilities: the list, the summary and one advisory's hosts.
import type { Vulnerability } from "../../api/types";
import type { DemoContext } from "../context";
import { json, problem, severityRank } from "../http";

export function registerVulnerabilityRoutes(ctx: DemoContext) {
  const { data, iso, vulnerabilities, route } = ctx;
  route("GET", "/api/v1/vulnerabilities", "vulnerabilities.read", (_, query) => {
    const flag = (name: string) => query.get(name) === "true";
    const items = vulnerabilities().filter((item: Vulnerability) =>
      (query.get("host") === null || item.agent_id === query.get("host")) &&
      (query.get("advisory") === null || item.advisory_id === query.get("advisory")) &&
      (query.get("severity") === null || item.severity === query.get("severity")) &&
      (query.get("cve") === null || item.cves.includes(query.get("cve") ?? "")) &&
      (query.get("exploited") === "false" ? !item.exploited : !flag("exploited") || item.exploited) && (!flag("reboot_needed") || item.reboot_needed))
      .sort((a, b) => Number(b.exploited) - Number(a.exploited) || (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9) || (b.epss ?? 0) - (a.epss ?? 0));
    return json({ items: items.slice(0, 1000), more_available: items.length > 1000, generated_at: iso() });
  });
  route("GET", "/api/v1/vulnerabilities/summary", "vulnerabilities.read", () => {
    const items = vulnerabilities();
    const hosts = new Map<string, { agent_id: string; hostname: string | null; open: number; serious: number }>();
    for (const item of items) {
      const host = hosts.get(item.agent_id) ?? { agent_id: item.agent_id, hostname: item.hostname ?? null, open: 0, serious: 0 };
      host.open += 1;
      if (item.severity === "critical" || item.severity === "important") host.serious += 1;
      hosts.set(item.agent_id, host);
    }
    return json({
      by_severity: (["critical", "important", "moderate", "low", "unrated"] as const).map((severity) => ({ severity, count: items.filter((i) => i.severity === severity).length })),
      exploited: items.filter((i) => i.exploited).length, hosts: hosts.size,
      no_fix: items.filter((i) => Array.isArray(i.packages) && (i.packages as { fixed: unknown }[]).every((p) => p.fixed == null)).length,
      reboot_hosts: new Set(items.filter((i) => i.reboot_needed).map((i) => i.agent_id)).size,
      top_hosts: [...hosts.values()].sort((a, b) => b.serious - a.serious || b.open - a.open).slice(0, 8),
      feed_last_imported_at: iso(Date.now() - 6 * 3600_000),
    });
  });
  route("GET", "/api/v1/vulnerabilities/advisories/{id}", "vulnerabilities.read", ({ id = "" }) => {
    const advisory = data.advisories.find((item) => item.id === decodeURIComponent(id));
    if (!advisory) return problem(404, "not_found", "Advisory not found");
    const items = vulnerabilities().filter((item) => item.advisory_id === advisory.id);
    return json({ cves: advisory.cves, hosts: { items, more_available: false, generated_at: iso() } });
  });
}
