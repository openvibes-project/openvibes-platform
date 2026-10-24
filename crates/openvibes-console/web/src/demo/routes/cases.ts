import { splitRef } from "../../panels/cases/cases";
import { seedCases } from "../caseSeed";
import { createCaseStore } from "../cases";
import { registerCaseListRoute } from "./caseList";
import type { DemoContext } from "../context";
import { browserPersistence, json, page, problem } from "../http";

export function registerCaseRoutes(ctx: DemoContext) {
  const { data, actor, me, permissions, rolesOf, visible, agentById, alarmList, findings, triageKey, hosts, hostPackages, audit, route, send } = ctx;
  // Cases: what an item is comes from the objects above, so triaging an
  // alarm or finding here changes what a case may record for it.
  const mitigated = (state: string | undefined) => state === "mitigated";
  const cases = createCaseStore({
    me: { user_id: me, username: actor, display_name: data.access.users.find((u) => u.user_id === me)?.display_name ?? actor },
    people: data.access.users,
    // The server's rule: enabled people holding cases.read through any role (Administrator holds it).
    get assignable() {
      return data.access.users.filter((u) => u.enabled && rolesOf(u.user_id).some((r) => r.permissions.includes("cases.read"))).map((u) => u.user_id);
    },
    canSee: visible,
    // The demo's one host scope (context.ts): every host when hosts.read reaches all.
    global: !ctx.scoped,
    hostname: (agentId) => data.agents.find((a) => a.id === agentId)?.hostname ?? null,
    facts: (kind, ref) => {
      const [first, rest] = splitRef(ref);
      if (kind === "alarm") {
        const alarm = alarmList().find((a) => a.id === ref);
        return alarm && { agent_id: alarm.agent_id, title: alarm.message, severity: alarm.severity, gone: mitigated(alarm.state) };
      }
      if (kind === "compliance_finding") {
        const [set, rule] = splitRef(rest);
        const finding = findings().find((f) => f.agent_id === first && f.rule_set_id === set && f.rule_id === rule);
        return finding && { agent_id: first, title: finding.message, severity: finding.severity, gone: mitigated(data.triage.get(triageKey(first, set, rule))?.state) };
      }
      if (kind === "vulnerability") {
        const row = data.vulnerabilities.find((v) => v.agent_id === first && v.advisory_id === rest && visible(v.agent_id));
        return row && { agent_id: first, title: row.title, severity: row.severity, gone: row.fixed_at != null };
      }
      if (kind === "host") {
        const agent = agentById(ref);
        return agent && { agent_id: agent.id, title: agent.hostname ?? agent.id, severity: null, gone: false };
      }
      const present = hosts().some((agent) => hostPackages(agent.id).some((p) => `${p.manager}/${p.name}` === ref));
      return present ? { agent_id: null, title: rest, severity: null, gone: false } : undefined;
    },
    audit: (action, target) => audit(action, target, "case"),
  }, () => seedCases(data), browserPersistence("openvibes.v2.demo.cases"));
  const listed = (query: URLSearchParams) => {
    const result = cases.list(query);
    return result.status === 200 ? json(page(result.body as unknown[], query)) : send(result);
  };
  route("GET", "/api/v1/cases", "cases.read", (_, query) => listed(query));
  registerCaseListRoute({ ...ctx, cases });
  // Setting or changing the assignee needs cases.assign too (cases/list.rs).
  const mayAssign = permissions.includes("cases.assign");
  const denied = () => problem(403, "permission_denied", "Permission denied");
  route("POST", "/api/v1/cases", "cases.write", (_, __, body) =>
    (typeof body.assignee_user_id === "string" && !mayAssign ? denied() : send(cases.create(body))));
  route("GET", "/api/v1/cases/for-item", "cases.read", (_, query) => send(cases.forItem(query)));
  route("GET", "/api/v1/cases/assignees", "cases.assign", () => send(cases.assignees()));
  route("GET", "/api/v1/cases/active-items", "cases.read", (_, query) => send(cases.activeItems(query)));
  // ponytail: the demo keeps no triage history; record changes here if the
  // demo's History tab should show them.
  route("GET", "/api/v1/triage-history", null, () => json({ items: [] }));
  route("GET", "/api/v1/cases/{id}", "cases.read", ({ id = "" }) => send(cases.get(id)));
  route("PUT", "/api/v1/cases/{id}", "cases.write", ({ id = "" }, _, body, headers) => {
    // The server reads If-Match first: without a valid one, the store answers 428 or 400.
    if (!/^"\d+"$/.test(headers["if-match"] ?? "")) return send(cases.update(id, body, headers["if-match"]));
    const current = cases.get(id);
    const was = (current.body as { assignee?: { user_id: string } | null } | undefined)?.assignee?.user_id ?? null;
    const next = typeof body.assignee_user_id === "string" ? body.assignee_user_id.toLowerCase() : null;
    return !mayAssign && current.status === 200 && was !== next ? denied() : send(cases.update(id, body, headers["if-match"]));
  });
  route("POST", "/api/v1/cases/{id}/notes", "cases.write", ({ id = "" }, _, body) => send(cases.addNote(id, body)));
  route("POST", "/api/v1/cases/{id}/items", "cases.write", ({ id = "" }, _, body) => send(cases.addItem(id, body)));
  route("DELETE", "/api/v1/cases/{id}/items/{item}", "cases.write", ({ id = "", item = "" }) => send(cases.removeItem(id, item)));
  route("PUT", "/api/v1/cases/{id}/items/{item}/outcome", "cases.write", ({ id = "", item = "" }, _, body) => send(cases.setOutcome(id, item, body)));
  return cases;
}
