// A vulnerability's page (GET /api/v1/vulnerabilities/{key}/summary and
// /{key}/hosts), answered as vulnerabilities/page.rs and the store's
// vuln_summary.rs answer them: one CVE (or a CVE-less advisory) over its
// host and advisory pairs in the vulnerabilities.read reach, or 404; an
// advisory with one CVE answers as that CVE, one with several 409; each
// action when its permission reaches a host with a pair (plan rulings 2, 7,
// 9-12). The demo keeps no vulnerability triage history, so History is empty.
import type { VulnHostsPage, VulnSummaryPage } from "../../api/types";
import type { createCaseStore } from "../cases";
import type { DemoContext } from "../context";
import { hasControl } from "../hostGroups";
import { json, problem, severityRank } from "../http";
import { cveFacts } from "./cveFacts";

const SEGMENTS = ["all", "open", "mitigated", "resolved"];
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const unique = (values: string[]) => [...new Set(values)].sort(byteOrder);
type Pkg = { name: string; installed?: string | null; fixed?: string | null };
const pkgs = (p: { packages: unknown }) => (Array.isArray(p.packages) ? (p.packages as Pkg[]) : []);
const segmentOf = (state: string) => (state === "open" || state === "mitigated" ? state : "resolved");

export function registerVulnSummaryRoutes(ctx: DemoContext & { cases: ReturnType<typeof createCaseStore> }) {
  const { data, route, reaches, cases } = ctx;
  const notFound = () => problem(404, "vulnerability_not_found", "Vulnerability not found");

  /** The key's pairs in reach, the canonical key, or the response that stands instead. */
  const resolve = (asked: string) => {
    if (!asked || [...asked].length > 256 || hasControl(asked) || asked.startsWith("CPE:")) return { response: notFound() };
    const advisory = data.advisories.find((a) => a.id === asked);
    const cves = advisory?.cves.map((c) => c.cve_id).sort(byteOrder) ?? [];
    const pairsOf = (ids: string[]) => data.vulnerabilities.filter((v) => ids.includes(v.advisory_id) && reaches("vulnerabilities.read", v.agent_id))
      .map((v) => ({ ...v, state: v.fixed_at != null ? "resolved" : v.triage_state }));
    if (advisory && cves.length > 1) {
      return pairsOf([advisory.id]).length === 0 ? { response: notFound() }
        : { response: problem(409, "advisory_has_several_cves", "The advisory names several CVEs; open the list filtered by it",
          { field_errors: cves.map((cve) => ({ field: "key", code: "cve", message: cve })) }) };
    }
    const key = advisory ? (cves[0] ?? advisory.id) : asked;
    const naming = data.advisories.filter((a) => a.id === key || a.cves.some((c) => c.cve_id === key)).map((a) => a.id);
    const pairs = pairsOf(naming);
    return pairs.length === 0 ? { response: notFound() } : { key, pairs };
  };

  route("GET", "/api/v1/vulnerabilities/{key}/summary", "vulnerabilities.read", ({ key: asked = "" }) => {
    const found = resolve(asked);
    if (!found.pairs) return found.response;
    const { key, pairs } = found;
    const advisories = unique(pairs.map((p) => p.advisory_id));
    const count = (id: string) => pairs.filter((p) => p.advisory_id === id).length;
    const lead = [...advisories].sort((a, b) => count(b) - count(a) || byteOrder(a, b))[0] ?? "";
    const leadPair = pairs.find((p) => p.advisory_id === lead) ?? pairs[0];
    const cve = data.advisories.flatMap((a) => a.cves).find((c) => c.cve_id === key);
    const facts = cveFacts(data.advisories, key, pairs);
    const open = pairs.filter((p) => p.state === "open");
    const fixed = unique(pairs.flatMap((p) => pkgs(p).flatMap((k) => (k.fixed ? [k.fixed] : []))));
    const people = unique(open.flatMap((p) => (p.assigned_to ? [p.assigned_to] : [])));
    const one = data.access.users.find((u) => u.username === people[0]);
    const osOf = (source: string) => { const [id = "", version = ""] = source.split("-"); return { os_id: id, os_version: version }; };
    const dists = unique(pairs.map((p) => p.source)).map((source) => {
      const here = pairs.filter((p) => p.source === source);
      const first = [...unique(here.map((p) => p.advisory_id))].sort((a, b) => count(b) - count(a) || byteOrder(a, b))[0] ?? "";
      const named = new Map(here.filter((p) => p.advisory_id === first).flatMap(pkgs).map((k) => [`${k.name}\u0000${k.fixed ?? ""}`, k]));
      return {
        ...osOf(source), advisory_id: first, url: here.find((p) => p.advisory_id === first)?.url ?? null,
        packages: [...named.values()].map((k) => ({ name: k.name, fixed: k.fixed ?? null })).sort((a, b) => byteOrder(a.name, b.name)),
        hosts: new Set(here.filter((p) => p.state !== "resolved").map((p) => p.agent_id)).size, reboot: here.some((p) => p.reboot_needed),
      };
    });
    const withFix = dists.filter((d) => d.packages.some((k) => k.fixed !== null)).length;
    const agents = unique(pairs.map((p) => p.agent_id));
    const anyHost = (permission: Parameters<typeof reaches>[0]) => agents.some((a) => reaches(permission, a));
    const names = unique(pairs.flatMap((p) => pkgs(p).map((k) => k.name)));
    const sameKeys = new Map<string, string>();
    for (const v of data.vulnerabilities) {
      if (!reaches("vulnerabilities.read", v.agent_id) || !pkgs(v).some((k) => names.includes(k.name))) continue;
      for (const k of v.cves.length ? v.cves : [v.advisory_id]) {
        const was = sameKeys.get(k);
        if (k !== key && (was === undefined || (severityRank[v.severity] ?? 9) < (severityRank[was] ?? 9))) sameKeys.set(k, v.severity);
      }
    }
    const severities = ["critical", "important", "moderate", "low", "unrated"]
      .map((value) => ({ value, count: [...sameKeys.values()].filter((s) => s === value).length })).filter((c) => c.count > 0);
    const alarms = data.alarms.filter((a) => agents.includes(a.agent_id) && a.state === "open" && reaches("alarms.read", a.agent_id))
      .sort((a, b) => (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9) || b.last_seen.localeCompare(a.last_seen));
    const caseRefs = new Map<string, { id: string; number: number; title: string }>();
    for (const p of pairs) {
      const ref = `${p.agent_id}/${p.advisory_id}`;
      const items = (cases.forItem(new URLSearchParams({ kind: "vulnerability", ref })).body as { items: { case: { case_id: string; number: number; title: string; status: string } }[] }).items;
      for (const { case: c } of items) if (c.status !== "closed") caseRefs.set(c.case_id, { id: c.case_id, number: c.number, title: c.title });
    }
    const triage = anyHost("vulnerabilities.triage");
    const body: VulnSummaryPage = {
      key,
      header: {
        title: leadPair?.title ?? key,
        severity: pairs.map((p) => p.severity).sort((a, b) => (severityRank[a] ?? 9) - (severityRank[b] ?? 9))[0] ?? "unrated",
        packages: names,
        fixed: fixed.length === 0 ? { kind: "none" } : fixed.length === 1 ? { kind: "one", version: fixed[0] ?? "" } : { kind: "several", count: fixed.length },
        open: open.length, total: pairs.length,
        assignee: people.length === 0 ? { kind: "none" } : people.length === 1 && one ? { kind: "one", id: one.user_id, name: one.display_name } : { kind: "several", count: people.length },
        kev_due: (facts ? facts.due : pairs.flatMap((p) => (p.kev_due ? [p.kev_due.slice(0, 10)] : [])).sort(byteOrder)[0]) ?? null,
        ransomware: pairs.some((p) => p.ransomware),
      },
      tiles: {
        open: open.length, total: pairs.length,
        fix: withFix === 0 ? { kind: "none" } : withFix === dists.length ? { kind: "all" } : { kind: "some", n: withFix, of: dists.length },
        epss: cve?.epss ?? null, epss_percentile: (facts ? facts.epss_percentile : leadPair?.epss_percentile) ?? null, cvss: cve?.cvss_score ?? null, cvss_version: cve?.cvss_version ?? null,
      },
      what_to_do: dists.sort((a, b) => byteOrder(a.os_id, b.os_id) || byteOrder(a.os_version, b.os_version)),
      details: {
        advisories: advisories.map((id) => ({ id, url: pairs.find((p) => p.advisory_id === id)?.url ?? null, source: pairs.find((p) => p.advisory_id === id)?.source ?? "" })),
        published: null,
        confidence: (() => {
          const sure = pairs.map((p) => ({ c: p.confidence, basis: p.match_basis })).sort((a, b) => a.c - b.c);
          return { min: sure[0]?.c ?? 0, max: sure[sure.length - 1]?.c ?? 0, basis: sure[0]?.basis ?? "" };
        })(),
        cvss_vector: null, cwe: cve?.cwe ?? [], description: cve?.description ?? null,
      },
      history: [],
      related: {
        alarms: reachesAny(ctx, "alarms.read") ? {
          items: alarms.slice(0, 3).map((a) => ({ id: Number(a.id), rule_id: a.rule_id, message: a.message, severity: a.severity, last_seen: a.last_seen })),
          total: alarms.length,
        } : null,
        cases: reachesAny(ctx, "cases.read") ? [...caseRefs.values()].sort((a, b) => b.number - a.number) : null,
        same_package: { cves: sameKeys.size, severities },
      },
      also_covers: unique(data.advisories.filter((a) => advisories.includes(a.id)).flatMap((a) => a.cves.map((c) => c.cve_id)).filter((c) => c !== key)),
      can: {
        triage, assign: triage, add_to_case: anyHost("cases.write") && anyHost("cases.read"),
        ask: anyHost("assistant.use"), export: anyHost("vulnerabilities.export"),
      },
    };
    return json(body);
  });

  route("GET", "/api/v1/vulnerabilities/{key}/hosts", "vulnerabilities.read", ({ key: asked = "" }, query) => {
    for (const k of query.keys()) if (!["segment", "offset", "limit"].includes(k)) return invalid("query");
    const segment = query.get("segment") || "all";
    if (!SEGMENTS.includes(segment)) return invalid("segment");
    const offset = Number(query.get("offset") || 0);
    const limit = Number(query.get("limit") || 50);
    if (!Number.isInteger(offset) || offset < 0 || offset > 100_000) return invalid("offset");
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) return invalid("limit");
    const found = resolve(asked);
    if (!found.pairs) return found.response;
    const users = data.access.users;
    const rows = found.pairs.map((p) => {
      const agent = data.agents.find((a) => a.id === p.agent_id);
      const who = users.find((u) => u.username === p.assigned_to);
      return {
        agent_id: p.agent_id, hostname: p.hostname ?? null, os: agent?.os_id ? `${agent.os_id} ${agent.os_version ?? ""}`.trim() : null,
        address: data.addresses.get(p.agent_id) ?? null, installed: unique(pkgs(p).flatMap((k) => (k.installed ? [k.installed] : []))).join(", "),
        state: p.state, assignee: who ? { id: who.user_id, name: who.display_name } : null, advisory_id: p.advisory_id,
        // No triage without a fixable package, or on a version-range (CPE) match, as vuln_hosts.rs.
        triage_version: p.advisory_id.startsWith("CPE:") || !pkgs(p).some((k) => k.fixed) ? null : p.triage_version,
      };
    }).sort((a, b) => byteOrder(a.hostname ?? "￿", b.hostname ?? "￿") || byteOrder(a.agent_id, b.agent_id) || byteOrder(a.advisory_id, b.advisory_id));
    const n = (s: string) => rows.filter((r) => segmentOf(r.state) === s).length;
    const chosen = rows.filter((r) => segment === "all" || segmentOf(r.state) === segment);
    const body: VulnHostsPage = {
      rows: chosen.slice(offset, offset + limit), total: chosen.length,
      segments: { all: rows.length, open: n("open"), mitigated: n("mitigated"), resolved: n("resolved") },
    };
    return json(body);
  });
}

const invalid = (field: string) => problem(400, "invalid_query", "Vulnerability query parameters are invalid",
  { field_errors: [{ field, code: "invalid", message: `The ${field} parameter is invalid` }] });

/** Whether the persona holds `permission` at all (the store reads Related only with it). */
function reachesAny(ctx: DemoContext, permission: Parameters<DemoContext["reaches"]>[0]) {
  return ctx.capabilities.some((c) => c.permission === permission);
}
