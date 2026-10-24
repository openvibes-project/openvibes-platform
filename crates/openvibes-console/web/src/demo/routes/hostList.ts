// The Hosts list (GET /api/v1/hosts), answered as hosts/list.rs and the
// store's host_list.rs answer it: single-value filters that AND together,
// each filter's counts with the others applied, the summary line, offset
// paging, rows inside the hosts.read scope and each problem count only
// where its own permission reaches (plan rulings 2–7).
import type { Agent, HostList } from "../../api/types";
import type { DemoContext } from "../context";
import type { DemoData } from "../data";
import { distribution, distributionName, hasControl, inCidr, inGroup, isActive, osFamily } from "../hostGroups";
import { json, problem } from "../http";
import { LATEST_AGENT_VERSION } from "./session";
import { openFailing } from "./checkList";
import { compareVersions, older } from "../versionOrder";

/** Code-unit order, as the server's COLLATE "C". */
const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

type Facet = "status" | "os" | "group" | "label" | "problems" | "agent";
type Host = {
  agent: Agent; status: string; family: string | null; address: string | null; labels: string[]; groups: string[];
  open_alarms: number | null; critical: number | null; failing: number | null; older: boolean | null; alarms_off: boolean;
};

const STATUS = ["online", "offline", "revoked", "imported"];
const PROBLEMS = ["critical", "alarms", "none"];
const AGENT = ["older", "latest"];
const SORTS = ["host", "heartbeat", "version", "problems"];
const statusOf = (a: Agent) => (a.status === "active" ? "online" : a.status === "stale" ? "offline" : a.status);
const noneOpen = (h: Host) => (h.open_alarms !== null || h.critical !== null || h.failing !== null)
  && !h.open_alarms && !h.critical && !h.failing;
const problemHit = (h: Host, p: string) => (p === "critical" ? (h.critical ?? 0) > 0 : p === "alarms" ? (h.open_alarms ?? 0) > 0 : noneOpen(h));
const invalid = (field: string) => problem(400, "invalid_query", "Host query parameters are invalid",
  { field_errors: [{ field, code: "invalid", message: `The ${field} parameter is invalid` }] });

/** A host's critical count as the host page and the Vulnerabilities list
 * show them by default (host_listed_critical): one per advisory, confidence
 * 80 or more, triage open. The group pages count the same. */
export const listedCritical = (data: DemoData, id: string) => new Set(data.vulnerabilities.filter((v) => v.agent_id === id
  && v.fixed_at == null && v.severity === "critical" && v.confidence >= 80 && v.triage_state === "open").map((v) => v.advisory_id)).size;

export function registerHostListRoutes(ctx: DemoContext) {
  const { data, route, visible, reaches, facts } = ctx;
  route("GET", "/api/v1/hosts", "hosts.read", (_, query) => {
    const get = (k: string) => query.get(k) || null;
    const chosen: Record<Facet, string | null> = { status: get("status"), os: get("os"), group: get("group"), label: get("label"), problems: get("problems"), agent: get("agent") };
    const closed: [string, string | null, string[]][] = [["status", chosen.status, STATUS], ["os", chosen.os, ["linux", "windows"]],
      ["problems", chosen.problems, PROBLEMS], ["agent", chosen.agent, AGENT], ["sort", get("sort"), SORTS], ["dir", get("dir"), ["asc", "desc"]]];
    for (const [field, value, allowed] of closed) if (value !== null && !allowed.includes(value)) return invalid(field);
    // The same text limits as the server; a group must have the demo's id
    // shape (grp-…), standing in for the server's UUID check.
    for (const [field, max] of [["q", 200], ["label", 64]] as const) {
      const v = get(field);
      if (v !== null && ([...v].length > max || hasControl(v))) return invalid(field);
    }
    if (chosen.group !== null && !/^grp-[a-z0-9-]{1,64}$/.test(chosen.group)) return invalid("group");
    const offset = Number(get("offset") ?? 0);
    const limit = Number(get("limit") ?? 50);
    if (!Number.isInteger(offset) || offset < 0 || offset > 100_000) return invalid("offset");
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) return invalid("limit");

    const latest = LATEST_AGENT_VERSION;
    const q = (get("q") ?? "").trim().toLowerCase();
    const base: Host[] = data.agents.filter((a) => visible(a.id)).flatMap((agent) => {
      const address = data.addresses.get(agent.id) ?? null;
      if (q && !(agent.hostname ?? "").toLowerCase().includes(q) && !agent.id.toLowerCase().startsWith(q)
        && !(address ?? "").startsWith(q) && !(q.includes("/") && address && inCidr(address, q))) return [];
      const f = facts(agent);
      return [{
        agent, address, status: statusOf(agent), family: osFamily(f), labels: [...(data.labels.get(agent.id) ?? [])].sort(byteOrder),
        // Members are active hosts only (console_host_in_group).
        groups: isActive(f) ? data.access.host_groups.filter((g) => inGroup(f, g)).map((g) => g.asset_group_id) : [],
        open_alarms: reaches("alarms.read", agent.id) ? data.alarms.filter((a) => a.agent_id === agent.id && a.state === "open").length : null,
        critical: reaches("vulnerabilities.read", agent.id) ? listedCritical(data, agent.id) : null,
        // Open failing checks, as the Compliance list and the host page count them.
        failing: reaches("compliance.read", agent.id)
          ? data.findings.filter((x) => x.agent_id === agent.id && openFailing(ctx, x, Date.parse(ctx.iso()))).length : null,
        older: agent.scanner_version ? older(agent.scanner_version, latest) : null,
        // Online with alarms off by a fault (alarms_status: off by choice is quiet).
        alarms_off: agent.status === "active" && agent.alarms?.state === "off" && agent.alarms.fault,
      }];
    });
    const holds = (h: Host, facet: Facet): boolean => {
      const v = chosen[facet];
      if (v === null) return true;
      switch (facet) {
        case "status": return h.status === v;
        case "os": return h.family === v;
        case "group": return h.groups.includes(v);
        case "label": return h.labels.includes(v);
        case "problems": return problemHit(h, v);
        case "agent": return v === "older" ? h.older === true : h.older === false;
      }
    };
    /** The hosts every filter but `skip` lets through. */
    const except = (skip: Facet | null) => base.filter((h) => (["status", "os", "group", "label", "problems", "agent"] as const).every((f) => f === skip || holds(h, f)));
    const tally = (hosts: Host[], keys: (h: Host) => string[]) => {
      const n = new Map<string, number>();
      for (const h of hosts) for (const k of keys(h)) n.set(k, (n.get(k) ?? 0) + 1);
      return n;
    };

    const byStatus = tally(except("status"), (h) => [h.status]);
    const byOs = tally(except("os"), (h) => (h.family ? [h.family] : []));
    const byProblem = tally(except("problems"), (h) => PROBLEMS.filter((p) => problemHit(h, p)));
    const byAgent = tally(except("agent"), (h) => (h.older === null ? [] : [h.older ? "older" : "latest"]));
    const byGroup = tally(except("group"), (h) => h.groups);
    const byLabel = tally(except("label"), (h) => h.labels);
    const groupOf = new Map(data.access.host_groups.map((g) => [g.asset_group_id, g]));
    // Groups with a matching host in reach, plus the chosen one when the hosts
    // scope reaches it (a member in reach, a global scope, or one of the scope's groups); by name.
    const scope = ctx.capabilities.find((c) => c.permission === "hosts.read")?.scope;
    const reachable = (g: string) => base.some((h) => h.groups.includes(g)) || scope?.kind === "global"
      || (scope?.kind === "asset_groups" && scope.asset_group_ids.includes(g));
    const groupIds = [...[...byGroup].filter(([, n]) => n > 0).map(([g]) => g),
      ...(chosen.group && groupOf.has(chosen.group) && !byGroup.get(chosen.group) && reachable(chosen.group) ? [chosen.group] : [])];
    // The 50 most used labels on matching hosts, plus the chosen one (when on a
    // visible host), all most used first: a chosen label with 0 sorts into place.
    const used = [...byLabel].filter(([l, n]) => n > 0 && l !== chosen.label).sort((a, b) => b[1] - a[1] || byteOrder(a[0], b[0])).slice(0, 50);
    if (chosen.label && data.agents.some((a) => visible(a.id) && (data.labels.get(a.id) ?? []).includes(chosen.label ?? ""))) used.push([chosen.label, byLabel.get(chosen.label) ?? 0]);
    const labelKeys = used.sort((a, b) => b[1] - a[1] || byteOrder(a[0], b[0])).map(([k]) => k);

    const matching = except(null);
    const dir = get("dir") === "desc" ? -1 : 1;
    const sum = (h: Host) => (h.open_alarms ?? 0) + (h.critical ?? 0) + (h.failing ?? 0);
    const last = (a: unknown, b: unknown) => (a == null ? 1 : 0) - (b == null ? 1 : 0); // NULLS LAST either way
    const key: Record<string, (a: Host, b: Host) => number> = {
      host: (a, b) => dir * (a.agent.hostname ?? "").toLowerCase().localeCompare((b.agent.hostname ?? "").toLowerCase()),
      heartbeat: (a, b) => last(a.agent.last_seen_at, b.agent.last_seen_at) || dir * (a.agent.last_seen_at ?? "").localeCompare(b.agent.last_seen_at ?? ""),
      version: (a, b) => compareVersions(a.agent.scanner_version, b.agent.scanner_version, dir),
      problems: (a, b) => dir * (sum(a) - sum(b)),
    };
    const order = key[get("sort") ?? "host"] ?? key.host;
    matching.sort((a, b) => order?.(a, b) || (a.agent.id < b.agent.id ? -1 : a.agent.id > b.agent.id ? 1 : 0));

    const byName = (a: string, b: string) => (groupOf.get(a)?.name ?? "").toLowerCase().localeCompare((groupOf.get(b)?.name ?? "").toLowerCase()) || a.localeCompare(b);
    const body: HostList = {
      items: matching.slice(offset, offset + limit).map((h) => {
        const groups = [...h.groups].sort(byName);
        const dist = distribution(facts(h.agent));
        return {
          id: h.agent.id, hostname: h.agent.hostname ?? null, address: h.address, status: h.status, last_seen_at: h.agent.last_seen_at ?? null,
          os: { id: h.agent.os_id ?? null, version: h.agent.os_version ?? null, distribution: dist && distributionName(dist), family: h.family },
          groups: groups.slice(0, 2).map((id) => ({ id, name: groupOf.get(id)?.name ?? id, kind: groupOf.get(id)?.kind ?? "manual" })),
          group_count: groups.length, labels: h.labels,
          problems: { open_alarms: h.open_alarms, critical: h.critical, failing: h.failing },
          agent: { version: h.agent.scanner_version ?? null, older: h.older }, alarms_off: h.alarms_off,
        };
      }),
      total: matching.length,
      counts: {
        status: STATUS.map((value) => ({ value, count: byStatus.get(value) ?? 0 })),
        os: [...byOs.entries()].sort((a, b) => byteOrder(a[0], b[0])).map(([value, count]) => ({ value, count })),
        group: groupIds.sort(byName).map((value) => ({ value, name: groupOf.get(value)?.name ?? value, kind: groupOf.get(value)?.kind ?? "manual", count: byGroup.get(value) ?? 0 })),
        label: labelKeys.map((value) => ({ value, count: byLabel.get(value) ?? 0 })),
        problems: PROBLEMS.map((value) => ({ value, count: byProblem.get(value) ?? 0 })),
        agent: AGENT.map((value) => ({ value, count: byAgent.get(value) ?? 0 })),
      },
      summary: {
        online: matching.filter((h) => h.status === "online").length,
        older_agent: matching.filter((h) => h.older === true).length,
        critical: matching.filter((h) => (h.critical ?? 0) > 0).length,
      },
      latest_agent_version: latest,
      generated_at: ctx.iso(),
    };
    return json(body);
  });
}
