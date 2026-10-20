// Compliance findings: groups by rule, each host's match, history and triage.
import type { GroupEndpoint, Severity } from "../../api/types";
import { allowedStates, noteRequired } from "../../panels/triage/triage";
import { demoMappings, pairView } from "../attack";
import type { DemoContext } from "../context";
import { json, page, problem } from "../http";

export function registerFindingRoutes(ctx: DemoContext) {
  const { data, iso, findings, groups, triageKey, setTriage, triageProblem, audit, route } = ctx;
  const endpoints = (ruleSetId: string, ruleId: string): GroupEndpoint[] => findings()
    .filter((finding) => finding.rule_set_id === ruleSetId && finding.rule_id === ruleId)
    .map((finding) => {
      const triage = data.triage.get(triageKey(finding.agent_id, ruleSetId, ruleId));
      return {
        agent_id: finding.agent_id, hostname: finding.hostname ?? null, authenticated: finding.authenticated,
        origin: finding.origin, first_observed_at: finding.first_observed_at, last_observed_at: finding.last_observed_at,
        outside_window: false, rule_version: finding.rule_version,
        triage_state: triage?.state ?? "open", triage_version: triage?.version ?? 0,
        assigned_to: triage?.assigned_to ?? null, accepted_until: triage?.accepted_until ?? null,
        // Demo: a mitigated host's agent later reported the match ended (P13).
        ended_at: triage?.state === "mitigated" ? finding.last_observed_at : null, end_approximate: false,
      };
    });

  route("GET", "/api/v1/compliance/summary", "compliance.read", () => {
    const open = findings().filter((f) => (data.triage.get(triageKey(f.agent_id, f.rule_set_id, f.rule_id))?.state ?? "open") === "open");
    const count = (severity: Severity) => open.filter((f) => f.severity === severity).length;
    return json({ total: open.length, impacted_agents: new Set(open.map((f) => f.agent_id)).size, critical: count("critical"), high: count("high"), medium: count("medium"), low: count("low") });
  });
  route("GET", "/api/v1/compliance/groups", "compliance.read", (_, query) =>
    json({ ...page(groups(query.get("agent_id") || undefined), query), generated_at: iso(), since: iso(Date.now() - 30 * 86_400_000) }));
  route("GET", "/api/v1/compliance/groups/{set}/{rule}/endpoints", "compliance.read", ({ set = "", rule = "" }, query) =>
    json({ ...page(endpoints(set, rule), query), generated_at: iso(), since: iso(Date.now() - 30 * 86_400_000) }));
  route("POST", "/api/v1/compliance/groups/{set}/{rule}/triage", "compliance.triage", ({ set = "", rule = "" }, _, body) => {
    const changes = (body.changes ?? []) as { agent_id: string; version: number }[];
    // The server's order: fields, then versions, then the workflow.
    const invalid = triageProblem(body, "compliance.triage") ?? (noteRequired.has(String(body.state)) && typeof body.note !== "string"
      ? problem(400, "invalid_triage", "Triage state, note, expiry, or selection is invalid") : null);
    if (invalid) return invalid;
    for (const change of changes) {
      const current = data.triage.get(triageKey(change.agent_id, set, rule))?.version ?? 0;
      if (current !== change.version) return problem(412, "stale_triage", "One or more selected endpoints changed; reload before saving");
    }
    const from = changes.map((change) => data.triage.get(triageKey(change.agent_id, set, rule))?.state ?? "open");
    if (!allowedStates(from).includes(String(body.state))) return problem(409, "invalid_transition", "Requested triage transition is not allowed");
    const updated = changes.map((change) => [change.agent_id, setTriage(change.agent_id, set, rule, body)]);
    audit("finding.triage", `${set}/${rule}`, "finding");
    return json({ updated });
  });
  route("GET", "/api/v1/compliance/history", "compliance.read", (_, query) => {
    const since = Date.parse(query.get("since") ?? "");
    if (Number.isNaN(since)) return problem(400, "invalid_query", "since is required");
    const day = 86_400_000;
    const items = findings().filter((f) => (query.get("agent_id") === null || f.agent_id === query.get("agent_id")) &&
      (query.get("rule_set_id") === null || f.rule_set_id === query.get("rule_set_id")) && (query.get("rule_id") === null || f.rule_id === query.get("rule_id")))
      .flatMap((f) => {
        // A mitigated finding stopped being observed a few days ago; the rest are still seen daily.
        const state = data.triage.get(triageKey(f.agent_id, f.rule_set_id, f.rule_id))?.state;
        const last = state === "mitigated" ? Date.parse(f.last_observed_at) - 3 * day : Date.parse(f.last_observed_at);
        const out = [];
        for (let at = last; at >= Math.max(since, Date.parse(f.first_observed_at)); at -= day) {
          out.push({ ...f, id: `${f.id}-${Math.floor(at / day)}`, observed_at: iso(at), observed_day: iso(at).slice(0, 10) });
        }
        return out;
      }).sort((a, b) => b.observed_at.localeCompare(a.observed_at));
    return json({ ...page(items, query), generated_at: iso() });
  });
  route("GET", "/api/v1/compliance/latest", "compliance.read", (_, query) => {
    const severity = query.get("severity");
    const agent = query.get("agent_id");
    const items = findings().filter((f) => (severity === null || f.severity === severity) && (agent === null || f.agent_id === agent));
    return json({ ...page(items, query), generated_at: iso() });
  });
  route("GET", "/api/v1/compliance/latest/{agent}/{set}/{rule}", "compliance.read", ({ agent, set, rule }) => {
    const finding = findings().find((f) => f.agent_id === agent && f.rule_set_id === set && f.rule_id === rule);
    return finding ? json(finding) : problem(404, "compliance_finding_not_found", "Compliance finding not found");
  });
  route("GET", "/api/v1/compliance/latest/{agent}/{set}/{rule}/rule/{finding}", "compliance.read", ({ agent, set, rule, finding: id }) => {
    const finding = findings().find((f) => f.agent_id === agent && f.rule_set_id === set && f.rule_id === rule && f.id === id);
    if (!finding) return problem(404, "compliance_finding_not_found", "Compliance finding not found");
    return json({ status: finding.detection ? "exact" : "unavailable", rule_set_id: set, rule_set_version: finding.detection?.rule_set_version ?? null,
      rule: finding.detection ? { id: rule, version: finding.rule_version, title: finding.message, expression: finding.detection.steps[0]?.expression,
        finding_message: finding.message, severity: finding.severity, confidence: finding.confidence, kind: "snapshot", programs: null, attack: (demoMappings[rule ?? ""] ?? []).map(pairView) } : null });
  });
  route("GET", "/api/v1/compliance/latest/{agent}/{set}/{rule}/triage", "compliance.read", ({ agent = "", set = "", rule = "" }) =>
    json(data.triage.get(triageKey(agent, set, rule)) ?? { state: "open", version: 0, rule_version: 3, note: null, assigned_to: null, accepted_until: null }));
  route("PUT", "/api/v1/compliance/latest/{agent}/{set}/{rule}/triage", "compliance.triage", ({ agent = "", set = "", rule = "" }, _, body) => {
    const invalid = triageProblem(body, "compliance.triage");
    if (invalid) return invalid;
    audit("finding.triage", `${set}/${rule}`, "finding");
    return json(setTriage(agent, set, rule, body));
  });
}
