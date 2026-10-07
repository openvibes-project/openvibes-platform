import { describe, expect, it } from "vitest";

import { createDemoServer } from "./server";

async function json(response: Response) {
  return response.json() as Promise<Record<string, unknown>>;
}

describe("demo server", () => {
  it("answers the session with the persona's capabilities", async () => {
    const server = createDemoServer({ persona: "viewer" });
    const session = await json(await server.handle("GET", "/api/v1/session"));
    const permissions = (session.capabilities as { permission: string }[]).map((c) => c.permission);
    expect(permissions).toEqual(["agents.read", "compliance.read", "vulnerabilities.read", "alarms.read"]);
  });

  it("refuses what the persona may not do, with problem details", async () => {
    const server = createDemoServer({ persona: "viewer" });
    const response = await server.handle("GET", "/api/v1/audit-events");
    expect(response.status).toBe(403);
    expect((await json(response)).code).toBe("forbidden");
  });

  it("pages agents with an opaque cursor and filters by state", async () => {
    const server = createDemoServer({ persona: "admin" });
    const first = await json(await server.handle("GET", "/api/v1/agents?limit=50"));
    expect((first.items as unknown[]).length).toBe(50);
    const second = await json(await server.handle("GET", `/api/v1/agents?limit=50&cursor=${String(first.next_cursor)}`));
    expect((second.items as { id: string }[])[0]?.id).toBe("agent-00051");
    const stale = await json(await server.handle("GET", "/api/v1/agents?state=stale&limit=100"));
    expect((stale.items as { status: string }[]).every((agent) => agent.status === "stale")).toBe(true);
  });

  it("applies bulk triage to a finding group and records it in the audit log", async () => {
    const server = createDemoServer({ persona: "admin" });
    const groups = await json(await server.handle("GET", "/api/v1/compliance/groups?limit=100"));
    const group = (groups.items as { rule_set_id: string; rule_id: string; triage_counts: { open: number } }[]).find((g) => g.triage_counts.open > 0);
    if (group === undefined) throw new Error("no groups");
    const endpoints = await json(await server.handle("GET", `/api/v1/compliance/groups/${group.rule_set_id}/${group.rule_id}/endpoints?limit=100`));
    const open = (endpoints.items as { agent_id: string; triage_state: string; triage_version: number }[]).filter((e) => e.triage_state === "open");
    const changes = open.map((e) => ({ agent_id: e.agent_id, version: e.triage_version }));
    const response = await server.handle("POST", `/api/v1/compliance/groups/${group.rule_set_id}/${group.rule_id}/triage`, { state: "investigating", changes });
    expect(response.status).toBe(200);
    const after = await json(await server.handle("GET", "/api/v1/compliance/groups?limit=100"));
    const updated = (after.items as { rule_id: string; triage_counts: { open: number } }[]).find((g) => g.rule_id === group.rule_id);
    expect(changes.length).toBeGreaterThan(0);
    expect(updated?.triage_counts.open).toBe(0);
    const audit = await json(await server.handle("GET", `/api/v1/audit-events?limit=1&since=${new Date(Date.now() - 86_400_000).toISOString()}`));
    expect((audit.items as { action: string }[])[0]?.action).toBe("finding.triage");
  });

  it("rejects a stale triage version with 412", async () => {
    const server = createDemoServer({ persona: "admin" });
    const groups = await json(await server.handle("GET", "/api/v1/compliance/groups?limit=1"));
    const group = (groups.items as { rule_set_id: string; rule_id: string }[])[0];
    if (group === undefined) throw new Error("no groups");
    const endpoints = await json(await server.handle("GET", `/api/v1/compliance/groups/${group.rule_set_id}/${group.rule_id}/endpoints?limit=1`));
    const endpoint = (endpoints.items as { agent_id: string }[])[0];
    const response = await server.handle("POST", `/api/v1/compliance/groups/${group.rule_set_id}/${group.rule_id}/triage`, { state: "mitigated", note: "patched", changes: [{ agent_id: endpoint?.agent_id, version: 99 }] });
    expect(response.status).toBe(412);
  });

  it("applies the server's triage field rules: expiry only for accepted risk, known assignees", async () => {
    const server = createDemoServer({ persona: "admin" });
    const groups = await json(await server.handle("GET", "/api/v1/compliance/groups?limit=1"));
    const group = (groups.items as { rule_set_id: string; rule_id: string }[])[0];
    if (group === undefined) throw new Error("no groups");
    const base = `/api/v1/compliance/groups/${group.rule_set_id}/${group.rule_id}`;
    const endpoint = ((await json(await server.handle("GET", `${base}/endpoints?limit=100`))).items as { agent_id: string; triage_state: string; triage_version: number }[])
      .find((item) => item.triage_state === "open");
    if (endpoint === undefined) throw new Error("no endpoints");
    const changes = [{ agent_id: endpoint.agent_id, version: endpoint.triage_version }];
    const future = new Date(Date.now() + 30 * 86_400_000).toISOString();
    const post = (body: Record<string, unknown>) => server.handle("POST", `${base}/triage`, { changes, ...body });
    if (endpoint.triage_state === "open") {
      expect((await json(await post({ state: "mitigated", note: "skipped a step" }))).code).toBe("invalid_transition");
    }
    expect((await post({ state: "accepted_risk" })).status).toBe(400);
    expect((await post({ state: "mitigated" })).status).toBe(400);
    expect((await post({ state: "accepted_risk", accepted_until: new Date(Date.now() - 1000).toISOString() })).status).toBe(400);
    expect((await post({ state: "investigating", accepted_until: future })).status).toBe(400);
    expect((await json(await post({ state: "investigating", assigned_to: "nobody" }))).code).toBe("invalid_assignee");
    expect((await post({ state: "investigating", assigned_to: "vic" })).status).toBe(400);
    expect((await post({ state: "investigating" })).status).toBe(200);
    changes[0] = { agent_id: endpoint.agent_id, version: endpoint.triage_version + 1 };
    expect((await post({ state: "accepted_risk", accepted_until: future })).status).toBe(400);
    expect((await post({ state: "accepted_risk", accepted_until: future, assigned_to: "sam", note: "vendor fix due" })).status).toBe(200);
    const saved = await json(await server.handle("GET", `/api/v1/compliance/latest/${endpoint.agent_id}/${group.rule_set_id}/${group.rule_id}/triage`));
    expect(saved).toMatchObject({ state: "accepted_risk", assigned_to: "sam", accepted_until: future });
    const listed = ((await json(await server.handle("GET", `${base}/endpoints?limit=100`))).items as { agent_id: string }[])
      .find((item) => item.agent_id === endpoint.agent_id);
    expect(listed).toMatchObject({ assigned_to: "sam", accepted_until: future });
  });

  it("lists a mitigated host's match as ended (P13), and open ones without an end", async () => {
    const server = createDemoServer({ persona: "admin" });
    const groups = (await json(await server.handle("GET", "/api/v1/compliance/groups?limit=100"))).items as { rule_set_id: string; rule_id: string }[];
    const all: { triage_state: string; ended_at: string | null; end_approximate: boolean }[] = [];
    for (const group of groups) {
      const page = await json(await server.handle("GET", `/api/v1/compliance/groups/${group.rule_set_id}/${group.rule_id}/endpoints?limit=100`));
      all.push(...(page.items as typeof all));
    }
    const mitigated = all.filter((e) => e.triage_state === "mitigated");
    expect(mitigated.length).toBeGreaterThan(0);
    expect(mitigated.every((e) => typeof e.ended_at === "string" && e.end_approximate === false)).toBe(true);
    expect(all.filter((e) => e.triage_state === "open").every((e) => e.ended_at === null)).toBe(true);
  });

  it("filters vulnerabilities and details an advisory with its CVEs and hosts", async () => {
    const server = createDemoServer({ persona: "admin" });
    const exploited = await json(await server.handle("GET", "/api/v1/vulnerabilities?exploited=true"));
    const items = exploited.items as { exploited: boolean; advisory_id: string }[];
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((item) => item.exploited)).toBe(true);
    const detail = await json(await server.handle("GET", `/api/v1/vulnerabilities/advisories/${encodeURIComponent(items[0]?.advisory_id ?? "")}`));
    expect((detail.cves as unknown[]).length).toBeGreaterThan(0);
    expect(((detail.hosts as { items: unknown[] }).items).length).toBeGreaterThan(0);
  });

  it("answers the assistant with a citation the console can open", async () => {
    const server = createDemoServer({ persona: "admin" });
    const reply = await json(await server.handle("POST", "/api/v1/assistant/messages", { question: "Which hosts are stale?" }));
    const citations = (reply.segments as { kind: string; target_kind?: string }[]).filter((s) => s.kind === "citation");
    expect(citations[0]?.target_kind).toBe("agent");
  });

  it("revokes an agent", async () => {
    const server = createDemoServer({ persona: "admin" });
    const response = await server.handle("POST", "/api/v1/agents/agent-00001/revoke", { reason: "decommissioned" });
    expect(response.status).toBe(200);
    const agent = await json(await server.handle("GET", "/api/v1/agents/agent-00001"));
    expect(agent.status).toBe("revoked");
  });

  it("rejects page sizes above the real API's maximum of 100", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await server.handle("GET", "/api/v1/agents?limit=101")).status).toBe(400);
    expect((await server.handle("GET", "/api/v1/compliance/groups?limit=250")).status).toBe(400);
    expect((await server.handle("GET", "/api/v1/agents?limit=100")).status).toBe(200);
  });

  it("requires since on audit queries, like the real API", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await server.handle("GET", "/api/v1/audit-events")).status).toBe(400);
    const recent = await json(await server.handle("GET", `/api/v1/audit-events?limit=100&since=${new Date(Date.now() - 3_600_000).toISOString()}`));
    expect((recent.items as { at: string }[]).every((e) => Date.parse(e.at) >= Date.now() - 3_600_000 - 1000)).toBe(true);
  });

  it("needs an Idempotency-Key to create an enrollment token, and a replay never returns the secret", async () => {
    const server = createDemoServer({ persona: "admin" });
    const body = { label: "x", max_uses: 1, expires_in_hours: 1 };
    expect((await server.handle("POST", "/api/v1/enrollment-tokens", body)).status).toBe(400);
    const key = { "idempotency-key": "key-0123456789abcdef" };
    const first = await json(await server.handle("POST", "/api/v1/enrollment-tokens", body, key));
    const again = await json(await server.handle("POST", "/api/v1/enrollment-tokens", body, key));
    expect(first.secret_available).toBe(true);
    expect(again).toMatchObject({ token_id: first.token_id, replayed: true, secret_available: false });
    expect(again.token).toBeUndefined();
  });

  it("creates a service account, issues a token once, and revokes it", async () => {
    const server = createDemoServer({ persona: "admin" });
    const created = await json(await server.handle("POST", "/api/v1/service-accounts", { name: "Backup job", role_id: "viewer" }));
    const id = String(created.service_account_id);
    const body = { label: "cron", expires_in_hours: 24 };
    expect((await server.handle("POST", `/api/v1/service-accounts/${id}/tokens`, body)).status).toBe(400);
    const token = await json(await server.handle("POST", `/api/v1/service-accounts/${id}/tokens`, body, { "idempotency-key": "svc-key-0123456789" }));
    expect(token.secret_available).toBe(true);
    expect((await server.handle("POST", `/api/v1/service-accounts/${id}/tokens/${String(token.token_id)}/revoke`)).status).toBe(200);
    const tokens = await json(await server.handle("GET", `/api/v1/service-accounts/${id}/tokens`));
    expect((tokens.items as { revoked: boolean }[])[0]?.revoked).toBe(true);
  });

  it("changes audit retention only with the current version in If-Match", async () => {
    const server = createDemoServer({ persona: "admin" });
    const policy = await json(await server.handle("GET", "/api/v1/audit-retention"));
    expect((await server.handle("PUT", "/api/v1/audit-retention", { retention_days: 400 })).status).toBe(428);
    expect((await server.handle("PUT", "/api/v1/audit-retention", { retention_days: 400 }, { "if-match": '"99"' })).status).toBe(412);
    const updated = await json(await server.handle("PUT", "/api/v1/audit-retention", { retention_days: 400 }, { "if-match": `"${String(policy.version)}"` }));
    expect(updated.retention_days).toBe(400);
  });

  it("previews a signed bundle and publishes it with the preview token", async () => {
    const server = createDemoServer({ persona: "admin" });
    const envelope = { rule_set_id: "baseline-linux", rule_set_version: 99, issuer_key_id: "ops-2026", expires_at_unix_ms: Date.now() + 86_400_000 };
    const preview = await json(await server.handle("POST", "/api/v1/rule-bundles/preview", envelope));
    expect(preview.version).toBe(99);
    expect((await server.handle("POST", "/api/v1/rule-bundles/publish", envelope)).status).toBe(428);
    const published = await server.handle("POST", "/api/v1/rule-bundles/publish", envelope, { "x-rule-preview-token": String(preview.preview_token) });
    expect(published.status).toBe(201);
    const sets = await json(await server.handle("GET", "/api/v1/rule-sets"));
    expect((sets.items as { rule_set_id: string; current_version: number }[]).find((set) => set.rule_set_id === "baseline-linux")?.current_version).toBe(99);
  });

  it("checks, saves, versions and deletes draft site rules", async () => {
    const server = createDemoServer({ persona: "admin" });
    const rule = { title: "Redis", severity: "high", confidence: 90, expression: "'6379' in facts['port.tcp.exposed']", finding_message: "Redis is exposed." };
    const url = "/api/v1/rule-drafts/site/port.redis.exposed";
    const bad = await json(await server.handle("POST", `${url}/check`, { ...rule, expression: "(((" }));
    expect(bad.ok).toBe(false);
    expect((await server.handle("PUT", url, { ...rule, expression: "(((" })).status).toBe(422);
    expect((await json(await server.handle("PUT", url, rule))).version).toBe(1);
    expect((await json(await server.handle("PUT", url, rule))).version).toBe(1);
    expect((await json(await server.handle("PUT", url, { ...rule, confidence: 80 }))).version).toBe(2);
    const alarm = { ...rule, expression: "event['process.name'] == 'sh'" };
    expect((await server.handle("PUT", "/api/v1/rule-drafts/site-alarms/a1", alarm)).status).toBe(422);
    expect((await server.handle("PUT", "/api/v1/rule-drafts/site-alarms/a1", { ...alarm, programs: ["nginx"] })).status).toBe(200);
    expect(((await json(await server.handle("GET", "/api/v1/rule-drafts/site"))).items as unknown[]).length).toBe(1);
    expect((await server.handle("DELETE", url)).status).toBe(204);
    expect((await server.handle("DELETE", url)).status).toBe(404);
    expect((await server.handle("GET", "/api/v1/rule-drafts/baseline")).status).toBe(404);
  });

  it("publishes drafts and reports what changed", async () => {
    const server = createDemoServer({ persona: "admin" });
    const rule = { title: "Redis", severity: "high", confidence: 90, expression: "'6379' in facts['port.tcp.exposed']", finding_message: "Redis is exposed." };
    const url = "/api/v1/rule-drafts/site";
    expect((await server.handle("POST", `${url}/publish`, { password: "pw" })).status).toBe(409);
    await server.handle("PUT", `${url}/r1`, rule);
    expect((await json(await server.handle("GET", `${url}/changes`))).added).toEqual(["r1"]);
    expect((await server.handle("POST", `${url}/publish`, { password: "wrong" })).status).toBe(403);
    expect((await json(await server.handle("POST", `${url}/publish`, { password: "pw" }))).version).toBe(1);
    expect((await server.handle("POST", `${url}/publish`, { password: "pw" })).status).toBe(409);
    await server.handle("PUT", `${url}/r1`, { ...rule, confidence: 70 });
    expect((await json(await server.handle("GET", `${url}/changes`))).changed).toEqual(["r1"]);
    expect((await json(await server.handle("POST", `${url}/publish`, { password: "pw" }))).version).toBe(2);
  });

  it("tests a rule against a host", async () => {
    const server = createDemoServer({ persona: "admin" });
    const agent = ((await json(await server.handle("GET", "/api/v1/agents"))).items as { id: string }[])[0]?.id ?? "";
    const url = "/api/v1/rule-drafts/site/r1/test";
    const rule = { title: "Redis", severity: "high", confidence: 90, expression: "'443' in facts['port.tcp.exposed']", finding_message: "Exposed." };
    expect((await json(await server.handle("POST", url, { agent_id: agent, rule }))).outcome).toBe("match");
    expect((await json(await server.handle("POST", url, { agent_id: agent, rule: { ...rule, expression: "'6379' in facts['port.tcp.exposed']" } }))).outcome).toBe("no_match");
    expect((await json(await server.handle("POST", url, { agent_id: agent, rule: { ...rule, expression: "'sshd' in facts['process.names']" } }))).outcome).toBe("unavailable");
    expect((await server.handle("POST", url, { agent_id: "nobody", rule })).status).toBe(404);
    expect((await server.handle("POST", "/api/v1/rule-drafts/site-alarms/a/test", { agent_id: agent, rule })).status).toBe(422);
  });

  it("reports the fleet's site rule sets", async () => {
    const server = createDemoServer({ persona: "admin" });
    const fleet = await json(await server.handle("GET", "/api/v1/site-rules/fleet"));
    const sets = fleet.sets as { rule_set_id: string; missing: number; current: number }[];
    expect(sets.map((set) => set.rule_set_id)).toEqual(["site", "site-alarms"]);
    expect(sets[0]?.missing).toBeGreaterThan(0);
    expect(String(fleet.paste)).toContain('id = "site-alarms"');
    expect((await server.handle("GET", "/api/v1/site-rules/fleet")).status).toBe(200);
  });

  it("keeps draft site rules from a persona without rules.write", async () => {
    const server = createDemoServer({ persona: "viewer" });
    expect((await server.handle("GET", "/api/v1/rule-drafts/site")).status).toBe(403);
  });

  it("answers finding history for a rule within since, like the real API", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await server.handle("GET", "/api/v1/compliance/history")).status).toBe(400);
    const since = new Date(Date.now() - 14 * 86_400_000).toISOString();
    const page = await json(await server.handle("GET", `/api/v1/compliance/history?since=${since}&rule_set_id=hardening-ssh&rule_id=SSH-002&limit=100`));
    const items = page.items as { rule_id: string; observed_at: string; observed_day: string }[];
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((item) => item.rule_id === "SSH-002" && Date.parse(item.observed_at) >= Date.parse(since))).toBe(true);
  });

  it("creates and edits asset groups", async () => {
    const server = createDemoServer({ persona: "admin" });
    const created = await json(await server.handle("POST", "/api/v1/access-control/asset-groups", { name: "Web", selectors: [{ key: "role", value: "web" }] }));
    const id = String(created.asset_group_id);
    expect(created.selectors).toEqual(["role=web"]);
    await server.handle("PUT", `/api/v1/access-control/asset-groups/${id}`, { name: "Web servers", selectors: [{ key: "role", value: "web" }, { key: "env", value: "prod" }] });
    const inventory = await json(await server.handle("GET", "/api/v1/access-control"));
    expect((inventory.asset_groups as { asset_group_id: string; name: string }[]).find((g) => g.asset_group_id === id)?.name).toBe("Web servers");
    expect((await server.handle("POST", "/api/v1/access-control/asset-groups", { name: "", selectors: [] })).status).toBe(422);
  });

  it("answers 404 for unknown routes", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await server.handle("GET", "/api/v1/nope")).status).toBe(404);
  });
  const layout = { schema: 1, widgets: [{ id: "w1", type: "number", x: 0, y: 0, w: 3, h: 2, config: { metric: "agents.active" } }] };

  it("runs the dashboard lifecycle with ETags and If-Match like the API", async () => {
    const server = createDemoServer({ persona: "admin" });
    const created = await server.handle("POST", "/api/v1/dashboards", { name: " Morning ", layout });
    expect(created.status).toBe(201);
    expect(created.headers.get("etag")).toBe('"1"');
    const dashboard = await json(created);
    expect(dashboard).toMatchObject({ name: "Morning", mine: true, version: 1 });
    const uri = `/api/v1/dashboards/${String(dashboard.dashboard_id)}`;
    expect((await server.handle("PUT", uri, { name: "x", layout })).status).toBe(428);
    expect((await server.handle("PUT", uri, { name: "x", layout }, { "if-match": '"1"' })).status).toBe(200);
    expect((await server.handle("PUT", uri, { name: "y", layout }, { "if-match": '"1"' })).status).toBe(412);
    expect((await server.handle("DELETE", uri)).status).toBe(204);
    expect((await server.handle("GET", uri)).status).toBe(404);
    expect((await server.handle("GET", "/api/v1/dashboards/not-a-uuid")).status).toBe(404);
  });

  it("refuses invalid layouts with the server's field paths", async () => {
    const server = createDemoServer({ persona: "admin" });
    const bad = await server.handle("POST", "/api/v1/dashboards", { name: "X", layout: { schema: 1, widgets: [{ id: "w1", type: "pie-chart", x: 0, y: 0, w: 3, h: 2, config: {} }] } });
    expect(bad.status).toBe(422);
    expect(((await json(bad)).field_errors as { field: string }[])[0]?.field).toBe("layout.widgets[0].type");
    expect((await server.handle("POST", "/api/v1/dashboards", { name: "", layout })).status).toBe(422);
    expect((await server.handle("POST", "/api/v1/dashboards", { name: "X" })).status).toBe(400);
  });

  it("a viewer never sees an unshared dashboard, and sharing needs the permission", async () => {
    const admin = createDemoServer({ persona: "admin" });
    const viewer = createDemoServer({ persona: "viewer" });
    const own = (await json(await viewer.handle("GET", "/api/v1/dashboards"))).items as { name: string; mine: boolean }[];
    expect(own.some((d) => d.name === "My morning check")).toBe(false);
    const mine = await json(await viewer.handle("POST", "/api/v1/dashboards", { name: "Viewer's", layout }));
    expect((await viewer.handle("PUT", `/api/v1/dashboards/${String(mine.dashboard_id)}/sharing`, { role_id: "viewer" })).status).toBe(403);
    expect((await admin.handle("PUT", "/api/v1/dashboards/d-admin-morning/sharing", { role_id: "no_such" })).status).toBe(422);
  });

  it("shows the seeded team dashboard to analysts read-only and lets them make it home", async () => {
    const analyst = createDemoServer({ persona: "analyst" });
    const items = (await json(await analyst.handle("GET", "/api/v1/dashboards"))).items as { dashboard_id: string; name: string; mine: boolean }[];
    const team = items.find((d) => d.name === "Analyst triage");
    expect(team?.mine).toBe(false);
    expect((await analyst.handle("PUT", `/api/v1/dashboards/${team?.dashboard_id ?? ""}`, { name: "x", layout }, { "if-match": '"1"' })).status).toBe(403);
    expect((await analyst.handle("PUT", "/api/v1/me/home", { dashboard_id: team?.dashboard_id })).status).toBe(200);
    expect((await json(await analyst.handle("GET", "/api/v1/me/home"))).dashboard_id).toBe(team?.dashboard_id);
    expect((await analyst.handle("PUT", "/api/v1/me/home", { dashboard_id: "d-admin-morning" })).status).toBe(404);
  });

  it("checks a save in the server's order: If-Match, then the body, then ownership and version", async () => {
    const server = createDemoServer({ persona: "admin" });
    const created = await json(await server.handle("POST", "/api/v1/dashboards", { name: "Order", layout }));
    const uri = `/api/v1/dashboards/${String(created.dashboard_id)}`;
    expect((await server.handle("PUT", uri, { name: "", layout }, { "if-match": '"9"' })).status).toBe(422);
    expect((await server.handle("PUT", uri, { name: "" })).status).toBe(428);
    expect((await server.handle("PUT", "/api/v1/dashboards/d-ola-triage", { name: "", layout }, { "if-match": '"1"' })).status).toBe(422);
  });

  it("limits an owner to 100 dashboards", async () => {
    const server = createDemoServer({ persona: "viewer" });
    for (let index = 0; index < 100; index += 1) await server.handle("POST", "/api/v1/dashboards", { name: `D${index}`, layout });
    expect((await server.handle("POST", "/api/v1/dashboards", { name: "One more", layout })).status).toBe(422);
  });

});

describe("demo alarms (P14)", () => {
  it("follows the server's rules for triage and suppressions", async () => {
    const analyst = createDemoServer({ persona: "analyst" });
    const list = await json(await analyst.handle("GET", "/api/v1/alarms"));
    const first = (list.items as { id: string; state: string }[]).find((a) => a.state === "open");
    expect(first).toBeDefined();
    const id = first?.id ?? "";
    const skip = await analyst.handle("PUT", `/api/v1/alarms/${id}/triage`, { state: "false_positive", note: "x" }, { "if-match": "\"1\"" });
    expect(skip.status).toBe(409);
    const step = await analyst.handle("PUT", `/api/v1/alarms/${id}/triage`, { state: "investigating" }, { "if-match": "\"1\"" });
    expect(step.status).toBe(200);
    const created = await analyst.handle("POST", "/api/v1/alarm-suppressions", { alarm_id: id, scope: "program", note: "noisy" });
    expect(created.status).toBe(201);
    const scoped = createDemoServer({ persona: "scoped_operator" });
    const refused = await scoped.handle("POST", "/api/v1/alarm-suppressions", { alarm_id: id, scope: "program", note: "noisy" });
    expect(refused.status).toBe(403);
  });
});

describe("demo metrics history", () => {
  const history = async (query: string) =>
    createDemoServer({ persona: "admin" }).handle("GET", `/api/v1/metrics/history?${query}`);

  it("returns at most `days` points ending today, deterministically", async () => {
    const body = await json(await history("metric=alarms.active&days=30"));
    const points = body.points as { day: string; value: number }[];
    expect(points).toHaveLength(30);
    expect(points.at(-1)?.day).toBe(new Date().toISOString().slice(0, 10));
    expect(points.every((p) => Number.isInteger(p.value) && p.value >= 0)).toBe(true);
    expect(((await json(await history("metric=alarms.active&days=30"))).points)).toEqual(points);
    expect(((await json(await history("metric=alarms.active&days=7"))).points as unknown[]).length).toBe(7);
  });

  it("takes only the real API's day counts, 30 by default", async () => {
    for (const days of ["5", "abc", "0"]) {
      const response = await history(`metric=alarms.active&days=${days}`);
      expect(response.status).toBe(422);
      expect(((await json(response)).field_errors as { code: string }[])[0]?.code).toBe("invalid_days");
    }
    expect(((await json(await history("metric=alarms.active"))).points as unknown[]).length).toBe(30);
  });

  it("ends on the same count the summaries show", async () => {
    const server = createDemoServer({ persona: "admin" });
    const last = async (metric: string) => ((await json(await server.handle("GET", `/api/v1/metrics/history?metric=${metric}&days=7`))).points as { value: number }[]).at(-1)?.value;
    const agents = await json(await server.handle("GET", "/api/v1/agents/summary"));
    const findings = await json(await server.handle("GET", "/api/v1/compliance/summary"));
    const vulns = await json(await server.handle("GET", "/api/v1/vulnerabilities/summary"));
    expect(await last("agents.stale")).toBe(agents.stale);
    expect(await last("compliance.open.critical")).toBe(findings.critical);
    expect(await last("vulns.exploited")).toBe(vulns.exploited);
  });

  it("refuses unknown metrics", async () => {
    expect((await history("metric=nope")).status).toBe(422);
  });
});
