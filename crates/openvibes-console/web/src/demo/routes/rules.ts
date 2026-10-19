// Rules: rule sets and signed bundles, draft site rules and publishing,
// ATT&CK coverage, and which rule sets each host runs.
import type { Agent, RuleDraft } from "../../api/types";
import { createAssignmentStore } from "../assignments";
import { demoAttack, demoMappings, pairView } from "../attack";
import type { DemoContext } from "../context";
import { browserPersistence, json, problem } from "../http";

export function registerRuleRoutes(ctx: DemoContext) {
  const { data, iso, actor, readsRules, agentById, visible, audit, route, send } = ctx;
  route("GET", "/api/v1/rule-sets", null, () => (readsRules() ? json({ items: data.ruleSets }) : problem(403, "permission_denied", "Access is not available")));
  route("GET", "/api/v1/rule-sets/{id}/bundles", null, ({ id = "" }) => (readsRules() ? json({ items: data.bundles.get(id) ?? [] }) : problem(403, "permission_denied", "Access is not available")));
  const previews = new Map<string, string>();
  const envelopeOf = (body: Record<string, unknown>) => ({
    set: String(body.rule_set_id ?? ""), version: Number(body.rule_set_version), key: String(body.issuer_key_id ?? ""), expires: Number(body.expires_at_unix_ms),
  });
  route("POST", "/api/v1/rule-bundles/preview", "rules.publish", (_, __, body) => {
    const e = envelopeOf(body);
    const set = data.ruleSets.find((candidate) => candidate.rule_set_id === e.set);
    if (!set || !Number.isInteger(e.version) || e.key === "") return problem(422, "invalid_envelope", "The envelope failed signature or trust validation");
    if (set.current_version != null && e.version <= set.current_version) return problem(409, "version_not_newer", `Version ${e.version} is not newer than ${set.current_version}`);
    const preview_token = `preview-${crypto.randomUUID()}`;
    previews.set(preview_token, JSON.stringify(e));
    return json({ rule_set_id: e.set, version: e.version, current_version: set.current_version ?? null, issuer_key_id: e.key, envelope_sha256: "demo".padEnd(64, "0"), expires_at_ms: e.expires, preview_token });
  });
  route("POST", "/api/v1/rule-bundles/publish", "rules.publish", (_, __, body, headers) => {
    const token = headers["x-rule-preview-token"];
    if (token === undefined) return problem(428, "preview_required", "Preview the bundle first");
    const e = envelopeOf(body);
    if (previews.get(token) !== JSON.stringify(e)) return problem(409, "preview_mismatch", "The envelope changed since its preview; preview it again");
    previews.delete(token);
    const set = data.ruleSets.find((candidate) => candidate.rule_set_id === e.set);
    if (!set) return problem(404, "not_found", "Rule set not found");
    set.current_version = e.version;
    set.current_issuer_key_id = e.key;
    set.current_expires_at_ms = e.expires;
    data.bundles.set(e.set, [{ version: e.version, bytes: JSON.stringify(body).length, created_at_ms: Date.now(), published_at: iso(), published_by: actor, envelope_sha256: "demo".padEnd(64, "0"), expires_at_ms: e.expires, issuer_key_id: e.key }, ...(data.bundles.get(e.set) ?? [])]);
    audit("rule_bundle.publish", e.set, "rule_set");
    return new Response(null, { status: 201 });
  });
  // Draft site rules. The demo's check is shallow: it mirrors the real
  // server's field names, not its CEL compiler.
  const drafts = new Map<string, Map<string, RuleDraft>>([["site", new Map()], ["site-alarms", new Map()]]);
  const attackOf = (body: Record<string, unknown>) => (Array.isArray(body.attack) ? body.attack : [])
    .map((pair: { tactic?: unknown; technique?: unknown }) => ({
      tactic: typeof pair.tactic === "string" ? pair.tactic : "",
      technique: typeof pair.technique === "string" ? pair.technique : null,
    }));
  const draftProblems = (set: string, body: Record<string, unknown>) => {
    const problems: { field: string; message: string }[] = [];
    const expression = String(body.expression ?? "");
    const depth = [...expression].reduce((d, c) => (d < 0 ? d : c === "(" || c === "[" ? d + 1 : c === ")" || c === "]" ? d - 1 : d), 0);
    if (expression.trim() === "" || depth !== 0) problems.push({ field: "expression", message: "not a valid expression" });
    if (!["info", "low", "medium", "high", "critical"].includes(String(body.severity))) problems.push({ field: "severity", message: "use info, low, medium, high or critical" });
    const programs = Array.isArray(body.programs) ? body.programs.map(String) : null;
    if (set === "site-alarms" && (programs === null || programs.length < 1 || programs.length > 8)) problems.push({ field: "programs", message: "name one to 8 distinct programs" });
    if (set === "site" && programs !== null) problems.push({ field: "programs", message: "only alarm rules have a program prefilter" });
    for (const pair of attackOf(body)) {
      if (!pairView(pair).known) problems.push({ field: "attack", message: `${pair.technique ?? pair.tactic} is not under ${pair.tactic} in ATT&CK ${demoAttack.version}` });
    }
    return problems;
  };
  route("GET", "/api/v1/rule-drafts/{set}", "site_rules.read", ({ set = "" }) => {
    const store = drafts.get(set);
    if (!store) return problem(404, "rule_set_not_found", "Only the site's own rule sets have drafts");
    return json({ items: [...store.values()].sort((a, b) => a.rule_id.localeCompare(b.rule_id)) });
  });
  route("POST", "/api/v1/rule-drafts/{set}/{id}/check", "site_rules.write", ({ set = "" }, __, body) => {
    if (!drafts.has(set)) return problem(404, "rule_set_not_found", "Only the site's own rule sets have drafts");
    const problems = draftProblems(set, body);
    return json({ ok: problems.length === 0, problems });
  });
  route("PUT", "/api/v1/rule-drafts/{set}/{id}", "site_rules.write", ({ set = "", id = "" }, __, body) => {
    const store = drafts.get(set);
    if (!store) return problem(404, "rule_set_not_found", "Only the site's own rule sets have drafts");
    const problems = draftProblems(set, body);
    if (problems.length > 0) return json({ ok: false, problems }, 422);
    const earlier = store.get(id);
    const next: RuleDraft = {
      rule_set_id: set, rule_id: id, title: String(body.title), severity: String(body.severity), confidence: Number(body.confidence), expression: String(body.expression),
      finding_message: String(body.finding_message), programs: set === "site-alarms" ? (body.programs as string[]) : null, attack: attackOf(body).map(pairView), updated_by: actor, updated_at: iso(), version: 1,
    };
    if (earlier) {
      const same = JSON.stringify({ ...earlier, version: 0, updated_at: "", updated_by: "" }) === JSON.stringify({ ...next, version: 0, updated_at: "", updated_by: "" });
      next.version = same ? earlier.version : earlier.version + 1;
    }
    store.set(id, next);
    audit("rule_draft.saved", `${set}/${id} v${next.version}`, "rule_draft");
    return json(next);
  });
  route("GET", "/api/v1/attack", null, () => (readsRules("rules.coverage.read") ? json(demoAttack) : problem(403, "permission_denied", "Access is not available")));
  route("GET", "/api/v1/rules/coverage", null, () => !readsRules("rules.coverage.read") ? problem(403, "permission_denied", "Access is not available") : json({
    attack_version: demoAttack.version, notice: demoAttack.notice, tactics: demoAttack.tactics, unverified_sets: [],
    rules: [
      ...data.rules.map((r) => ({ rule_set_id: r.ruleSetId, rule_id: r.ruleId, title: r.message.split(" listens")[0] ?? r.ruleId, kind: "snapshot", severity: r.severity, draft: false, attack: (demoMappings[r.ruleId] ?? []).map(pairView) })),
      ...[...new Map(data.alarms.map((a) => [a.rule_id, a])).values()].map((a) => ({ rule_set_id: "baseline-alarms", rule_id: a.rule_id, title: a.message, kind: "process_event", severity: a.severity, draft: false, attack: (demoMappings[a.rule_id] ?? []).map(pairView) })),
      ...[...drafts.values()].flatMap((store) => [...store.values()]).map((d) => ({ rule_set_id: d.rule_set_id, rule_id: d.rule_id, title: d.title, kind: d.rule_set_id === "site-alarms" ? "process_event" : "snapshot", severity: d.severity, draft: true, attack: d.attack })),
    ],
  }));
  route("DELETE", "/api/v1/rule-drafts/{set}/{id}", "site_rules.write", ({ set = "", id = "" }) => {
    if (!drafts.get(set)?.delete(id)) return problem(404, "draft_not_found", "No such draft");
    audit("rule_draft.deleted", `${set}/${id}`, "rule_draft");
    return new Response(null, { status: 204 });
  });
  route("POST", "/api/v1/rule-drafts/{set}/{id}/test", "site_rules.test", ({ set = "" }, __, body) => {
    if (!drafts.has(set)) return problem(404, "rule_set_not_found", "Only the site's own rule sets have drafts");
    if (set !== "site") return problem(422, "alarm_test_unsupported", "Alarm rules run on process starts, which the platform doesn't hold; test them on a host");
    if (!agentById(String(body.agent_id ?? ""))) return problem(404, "host_not_found", "No such host");
    const rule = (body.rule ?? {}) as Record<string, unknown>;
    if (draftProblems(set, rule).length > 0) return problem(422, "invalid_rule", "The rule does not pass the agent's checks yet");
    const expression = String(rule.expression);
    // The demo knows two hosts' ports: enough to show every outcome.
    const exposed = ["22", "443"];
    const facts = { packages: 312, listeners: 4, listeners_reported_at: iso() };
    if (!/facts\['(port|package)\./.test(expression)) return json({ outcome: "unavailable", evidence: [], message: "The platform doesn't hold a fact this rule reads. The platform rebuilds only packages and listening ports; the agent evaluates the rest.", facts });
    const port = /'(\d+)' in facts\['port\.tcp\.exposed'\]/.exec(expression)?.[1];
    const matched = port === undefined ? expression.includes("package.names") : exposed.includes(port);
    return json({ outcome: matched ? "match" : "no_match", evidence: matched ? [port === undefined ? "package.names" : "port.tcp.exposed"] : [], message: null, facts });
  });
  // Publishing: the demo "signs" by remembering the drafts as the published set.
  const published = new Map<string, { version: number; rules: Map<string, string> }>();
  const draftChanges = (set: string, store: Map<string, RuleDraft>) => {
    const before = published.get(set);
    const out = { published_version: before?.version ?? null, added: [] as string[], changed: [] as string[], removed: [] as string[], unchanged: 0 };
    for (const [id, draft] of [...store].sort(([a], [b]) => a.localeCompare(b))) {
      const old = before?.rules.get(id);
      if (old === undefined) out.added.push(id);
      else if (old === JSON.stringify({ ...draft, version: 0, updated_at: "", updated_by: "" })) out.unchanged += 1;
      else out.changed.push(id);
    }
    out.removed = [...(before?.rules.keys() ?? [])].filter((id) => !store.has(id)).sort((a, b) => a.localeCompare(b));
    return out;
  };
  route("GET", "/api/v1/site-rules/fleet", "site_rules.read", () => {
    const sets = ["site", "site-alarms"].map((id) => ({ rule_set_id: id, published_version: published.get(id)?.version ?? null, current: 0, behind: 0, refused: 0, missing: 0 }));
    const hosts: { agent_id: string; hostname: string | null; site: string; site_alarms: string }[] = [];
    const stateOf = (agent: Agent, set: (typeof sets)[number]) => {
      const entry = agent.rule_sets.find((candidate) => candidate.id === set.rule_set_id);
      if (!entry?.version) return "missing";
      if (entry.refused) return "refused";
      return set.published_version !== null && entry.version < set.published_version ? "behind" : "current";
    };
    for (const agent of data.agents.filter((candidate) => visible(candidate.id) && (candidate.status === "active" || candidate.status === "stale"))) {
      const states = sets.map((set) => stateOf(agent, set));
      sets.forEach((set, index) => { set[states[index] as "current" | "behind" | "refused" | "missing"] += 1; });
      if (states.some((state) => state !== "current") && hosts.length < 200) hosts.push({ agent_id: agent.id, hostname: agent.hostname ?? null, site: states[0] ?? "missing", site_alarms: states[1] ?? "missing" });
    }
    const line = (id: string) => `[[rule_sets]]\nid = "${id}"\ntrusted_keys = [{ issuer_key_id = "site.key", public_key = "DEMO-PUBLIC-KEY-NOT-REAL" }]\n`;
    return json({ sets, reporting: hosts.length, not_reporting: 0, hosts, hosts_truncated: false, paste: line("site") + line("site-alarms") });
  });
  route("GET", "/api/v1/rule-drafts/{set}/changes", "site_rules.read", ({ set = "" }) => {
    const store = drafts.get(set);
    if (!store) return problem(404, "rule_set_not_found", "Only the site's own rule sets have drafts");
    return json(draftChanges(set, store));
  });
  route("POST", "/api/v1/rule-drafts/{set}/publish", "site_rules.publish", ({ set = "" }, __, body) => {
    const store = drafts.get(set);
    if (!store) return problem(404, "rule_set_not_found", "Only the site's own rule sets have drafts");
    if (store.size === 0) return problem(409, "no_rules", "Write at least one rule before publishing");
    const diff = draftChanges(set, store);
    if (diff.added.length + diff.changed.length + diff.removed.length === 0) return problem(409, "nothing_changed", "The drafts match what is published");
    if (String(body.password ?? "") === "" || body.password === "wrong") return problem(403, "wrong_password", "Wrong password");
    const version = (published.get(set)?.version ?? 0) + 1;
    published.set(set, { version, rules: new Map([...store].map(([id, draft]) => [id, JSON.stringify({ ...draft, version: 0, updated_at: "", updated_by: "" })])) });
    audit("rule_bundle.publish", `${set} v${version}`, "rule_set");
    return json({ rule_set_id: set, version, expires_at_ms: Date.now() + 365 * 86_400_000, rules: store.size }, 201);
  });

  const assignments = createAssignmentStore(data, (setId) => audit("rules.assignment.change", setId, "rule_set"), browserPersistence("openvibes.v2.demo.rule-assignment"));
  route("GET", "/api/v1/rule-set-assignments", null, () => (readsRules("rules.assignment.read") ? json(assignments.list()) : problem(403, "permission_denied", "Access is not available")));
  route("PUT", "/api/v1/rule-set-assignments/{set}", "rules.assignment.write", ({ set = "" }, _, body) => send(assignments.setDefault(set, body)));
  route("PUT", "/api/v1/rule-set-assignments/{set}/groups/{group}", "rules.assignment.write", ({ set = "", group = "" }, _, body) => send(assignments.setGroup(set, group, body)));
  route("DELETE", "/api/v1/rule-set-assignments/{set}/groups/{group}", "rules.assignment.write", ({ set = "", group = "" }) => send(assignments.clearGroup(set, group)));
  route("GET", "/api/v1/agents/{id}/rule-set-assignments", "hosts.read", ({ id = "" }) => {
    const agent = agentById(id);
    return agent ? json(assignments.host(agent)) : problem(404, "agent_not_found", "Agent not found");
  });
}
