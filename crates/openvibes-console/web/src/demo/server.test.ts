import { describe, expect, it, vi } from "vitest";

import { buildDemoData } from "./data";
import { createDemoServer } from "./server";

async function json(response: Response) {
  return response.json() as Promise<Record<string, unknown>>;
}

describe("demo server", () => {
  it("shows only compliance rules OpenVIBES ships (the baseline), so its screenshots stay honest", async () => {
    // openvibes-rules baseline/rules.json: the demo must not invent checks
    // the product does not have (website screenshots come from the demo).
    const shipped = new Set([
      "port.docker_api.exposed", "port.telnet.exposed", "port.rsh.exposed", "port.vnc.exposed", "port.redis.exposed",
      "port.mongodb.exposed", "port.elasticsearch.exposed", "port.memcached.exposed", "port.ftp.exposed", "port.smb.exposed",
      "port.snmp.exposed", "port.postgresql.exposed", "port.mysql.exposed", "port.ssh.exposed",
      "package.telnet_server.installed", "package.rsh_server.installed",
    ]);
    const data = buildDemoData();
    expect(data.findings.length).toBeGreaterThan(0);
    for (const finding of data.findings) {
      expect(finding.rule_set_id).toBe("baseline");
      expect(shipped.has(finding.rule_id), finding.rule_id).toBe(true);
    }
  });

  it("answers the session with the persona's capabilities", async () => {
    const server = createDemoServer({ persona: "viewer" });
    const session = await json(await server.handle("GET", "/api/v1/session"));
    const permissions = (session.capabilities as { permission: string }[]).map((c) => c.permission);
    expect(permissions).toEqual([
      "alarms.read", "alarms.suppressions.read", "compliance.read", "vulnerabilities.read", "hosts.read",
      "cases.read", "rules.read", "rules.coverage.read",
    ]);
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
    const response = await server.handle("POST", `/api/v1/compliance/groups/${group.rule_set_id}/${group.rule_id}/triage`, { state: "mitigated", note: "patched", changes });
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
    expect((await json(await post({ state: "investigating" }))).code).toBe("invalid_transition");
    expect((await post({ state: "accepted_risk" })).status).toBe(400);
    expect((await post({ state: "mitigated" })).status).toBe(400);
    expect((await post({ state: "accepted_risk", accepted_until: new Date(Date.now() - 1000).toISOString() })).status).toBe(400);
    expect((await post({ state: "open", accepted_until: future })).status).toBe(400);
    expect((await json(await post({ state: "open", assigned_to: "nobody" }))).code).toBe("invalid_assignee");
    expect((await post({ state: "open", assigned_to: "vic" })).status).toBe(400);
    expect((await post({ state: "open" })).status).toBe(200);
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

  it("shows a blocked web search as blocked, not as a failed lookup", async () => {
    const server = createDemoServer({ persona: "admin" });
    const reply = await json(await server.handle("POST", "/api/v1/assistant/messages", { question: "Search the web for platform.lab problem" }));
    expect(reply.internet).toEqual([{ kind: "blocked", text: "Web search blocked: the query contained internal data", url: null, number: null }]);
  });

  it("quotes the finding's own message when asked what to fix first", async () => {
    // The rule messages are whole sentences (the shipped baseline): lowercased
    // into brackets they read "(the unencrypted docker api … 2376., 4 hosts open)".
    const server = createDemoServer({ persona: "admin" });
    const reply = await json(await server.handle("POST", "/api/v1/assistant/messages", { question: "What should I fix first?" }));
    const text = (reply.segments as { kind: string; text?: string }[]).filter((s) => s.kind === "text").map((s) => s.text).join("");
    expect(text).toContain("The unencrypted Docker API (tcp 2375)");
    expect(text).not.toContain(".,");
    expect(text).toMatch(/Open on \d+ hosts?\./);
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
    const created = await json(await server.handle("POST", "/api/v1/service-accounts", { name: "Backup job", role_ids: ["viewer"] }));
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

  it("changes the assistant internet setting only with If-Match and a URL at level 2", async () => {
    const server = createDemoServer({ persona: "admin" });
    const setting = await json(await server.handle("GET", "/api/v1/assistant-internet"));
    const body = { level: 2, searxng_url: null, internal_domains: [] };
    expect((await server.handle("PUT", "/api/v1/assistant-internet", body)).status).toBe(428);
    expect((await server.handle("PUT", "/api/v1/assistant-internet", body, { "if-match": `"${String(setting.version)}"` })).status).toBe(400);
    const ok = await json(await server.handle("PUT", "/api/v1/assistant-internet", { ...body, searxng_url: "https://s.example.test" }, { "if-match": `"${String(setting.version)}"` }));
    expect(ok.level).toBe(2);
  });

  it("answers Test connection only at level 2", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect(await json(await server.handle("POST", "/api/v1/assistant-internet/test"))).toEqual({ ok: false, detail: "web search is off" });
    const setting = await json(await server.handle("GET", "/api/v1/assistant-internet"));
    await server.handle("PUT", "/api/v1/assistant-internet", { level: 2, searxng_url: "https://s.example.test", internal_domains: [] }, { "if-match": `"${String(setting.version)}"` });
    expect(await json(await server.handle("POST", "/api/v1/assistant-internet/test"))).toEqual({ ok: true, detail: "5 results" });
    expect((await createDemoServer({ persona: "viewer" }).handle("POST", "/api/v1/assistant-internet/test")).status).toBe(403);
  });

  it("refuses assistant internet settings the real API refuses", async () => {
    const server = createDemoServer({ persona: "admin" });
    const put = async (body: object) => {
      const setting = await json(await server.handle("GET", "/api/v1/assistant-internet"));
      return server.handle("PUT", "/api/v1/assistant-internet", { level: 2, internal_domains: [], ...body }, { "if-match": `"${String(setting.version)}"` });
    };
    for (const url of ["http://search.example.com", "http://8.8.8.8", "ftp://x", "https://u@x", "https://", "https://x/?q=1"]) expect((await put({ searxng_url: url })).status, url).toBe(400);
    for (const domains of [["Corp.Example"], ["bad_name"], ["-a"], Array.from({ length: 51 }, (_, i) => `d${String(i)}`)]) expect((await put({ searxng_url: "https://s.example.test", internal_domains: domains })).status).toBe(400);
    for (const url of ["https://s.example.test", "http://localhost:8080", "http://192.168.1.2", "http://172.16.0.1", "http://[fd00::1]"]) expect((await put({ searxng_url: url, internal_domains: ["intranet", "corp.example"] })).status, url).toBe(200);
    expect((await put({ searxng_url: "http://172.32.0.1" })).status).toBe(400);
  });

  it("answers finding history for a rule within since, like the real API", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await server.handle("GET", "/api/v1/compliance/history")).status).toBe(400);
    const since = new Date(Date.now() - 14 * 86_400_000).toISOString();
    const page = await json(await server.handle("GET", `/api/v1/compliance/history?since=${since}&rule_set_id=baseline&rule_id=port.ssh.exposed&limit=100`));
    const items = page.items as { rule_id: string; observed_at: string; observed_day: string }[];
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((item) => item.rule_id === "port.ssh.exposed" && Date.parse(item.observed_at) >= Date.parse(since))).toBe(true);
  });

  it("answers 404 for unknown routes", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await server.handle("GET", "/api/v1/nope")).status).toBe(404);
  });
});

describe("demo alarms (P14)", () => {
  it("follows the server's rules for triage and suppressions", async () => {
    const analyst = createDemoServer({ persona: "analyst" });
    const list = await json(await analyst.handle("GET", "/api/v1/alarms"));
    const first = (list.items as { id: string; state: string }[]).find((a) => a.state === "open");
    expect(first).toBeDefined();
    const id = first?.id ?? "";
    // Any state to any other in one step; a close needs a note; investigating is retired.
    const bare = await analyst.handle("PUT", `/api/v1/alarms/${id}/triage`, { state: "false_positive" }, { "if-match": "\"1\"" });
    expect(bare.status).toBe(400);
    const retired = await analyst.handle("PUT", `/api/v1/alarms/${id}/triage`, { state: "investigating" }, { "if-match": "\"1\"" });
    expect(retired.status).toBe(409);
    const closed = await analyst.handle("PUT", `/api/v1/alarms/${id}/triage`, { state: "false_positive", note: "x" }, { "if-match": "\"1\"" });
    expect(closed.status).toBe(200);
    const body = { alarm_id: id, what: "program", where: { kind: "host" }, for_days: null, reason: "noisy" };
    const created = await analyst.handle("POST", "/api/v1/alarm-suppressions", body);
    expect(created.status).toBe(201);
    expect((await analyst.handle("POST", "/api/v1/alarm-suppressions", { ...body, scope: "program" })).status).toBe(422);
    // Operators hold no alarms.suppress (src/demo/suppressions.test.ts covers the rest).
    const scoped = createDemoServer({ persona: "scoped_operator" });
    expect((await scoped.handle("POST", "/api/v1/alarm-suppressions", body)).status).toBe(403);
  });
});

describe("demo bulk triage (triage v2)", () => {
  it("closes with a note, files into one open case and expands an advisory to its hosts", async () => {
    const analyst = createDemoServer({ persona: "analyst" });
    const list = await json(await analyst.handle("GET", "/api/v1/alarms"));
    const filed0 = await json(await analyst.handle("GET", "/api/v1/cases/active-items?kind=alarm"));
    const inCases = new Set((filed0.items as { ref: string }[]).map((i) => i.ref));
    const ids = (list.items as { id: string }[]).filter((a) => !inCases.has(a.id)).map((a) => ({ id: a.id }));
    expect(ids.length).toBeGreaterThan(0);
    const post = async (kind: string, body: Record<string, unknown>) => {
      const response = await analyst.handle("POST", `/api/v1/${kind}/bulk`, body);
      return { status: response.status, body: await json(response) };
    };
    expect((await post("alarms", { action: "state", state: "mitigated", items: ids })).status).toBe(400);
    expect((await post("alarms", { action: "state", state: "mitigated", note: "patched", items: ids })).body).toMatchObject({ changed: ids.length, skipped: [] });
    const filed = await post("alarms", { action: "case", new_case_title: "Two alarms", new_case_severity: "high", items: ids });
    expect(filed.body).toMatchObject({ changed: ids.length });
    expect(typeof filed.body.case_number).toBe("number");
    const again = await post("alarms", { action: "case", new_case_title: "Again", items: ids });
    expect(again.body.changed).toBe(0);
    expect((again.body.skipped as { reason: string }[]).every((s) => s.reason === "in another open case")).toBe(true);
    const active = await json(await analyst.handle("GET", "/api/v1/cases/active-items?kind=alarm"));
    expect((active.items as { ref: string }[]).map((i) => i.ref)).toEqual(expect.arrayContaining(ids.map((i) => i.id)));
    const vulns = await json(await analyst.handle("GET", "/api/v1/vulnerabilities"));
    const advisory = (vulns.items as { advisory_id: string }[])[0]?.advisory_id ?? "";
    const hosts = (vulns.items as { advisory_id: string }[]).filter((v) => v.advisory_id === advisory).length;
    expect((await post("vulnerabilities", { action: "state", state: "false_positive", note: "not affected", items: [{ advisory_id: advisory }] })).body.changed).toBe(hosts);
    const after = await json(await analyst.handle("GET", "/api/v1/vulnerabilities"));
    expect((after.items as { advisory_id: string; triage_state: string }[]).filter((v) => v.advisory_id === advisory).every((v) => v.triage_state === "false_positive")).toBe(true);
  });
});

describe("demo general settings", () => {
  it("lists, saves with an audit line, and refuses like the server", async () => {
    const server = createDemoServer({ persona: "admin" });
    const first = await json(await server.handle("GET", "/api/v1/settings"));
    expect((first.items as { key: string; value: unknown }[]).map((i) => [i.key, i.value])).toEqual([["suppressions.require_approval", false], ["sso.remove_inactive_days", 90]]);
    const saved = await server.handle("PATCH", "/api/v1/settings/suppressions.require_approval", { value: true });
    expect(saved.status).toBe(200);
    const after = await json(await server.handle("GET", "/api/v1/settings"));
    expect(after.recent).toMatchObject([{ key: "suppressions.require_approval", old: null, new: true }]);
    const audit = await json(await server.handle("GET", `/api/v1/audit-events?limit=1&since=${new Date(Date.now() - 86_400_000).toISOString()}`));
    expect((audit.items as { action: string }[])[0]?.action).toBe("settings.changed");
    const bad = await server.handle("PATCH", "/api/v1/settings/sso.remove_inactive_days", { value: 0 });
    expect(bad.status).toBe(422);
    expect(await json(bad)).toMatchObject({ code: "invalid_setting", field_errors: [{ field: "value", message: "Use a whole number from 1 to 3650" }] });
    expect((await server.handle("PATCH", "/api/v1/settings/nope", { value: 1 })).status).toBe(404);
    const viewer = createDemoServer({ persona: "viewer" });
    expect((await viewer.handle("GET", "/api/v1/settings")).status).toBe(403);
    expect((await viewer.handle("PATCH", "/api/v1/settings/sso.remove_inactive_days", { value: 5 })).status).toBe(403);
  });

  it("ignores stored state that does not fit (a hand-edited or old localStorage)", async () => {
    const store = new Map([["openvibes.v2.demo.settings", JSON.stringify({
      recent: "x", values: { "sso.remove_inactive_days": { value: "90", changed_at: "t", changed_by: "a" }, "suppressions.require_approval": { value: 1, changed_at: "t", changed_by: "a" } },
    })]]);
    vi.stubGlobal("localStorage", { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => { store.set(k, v); } });
    try {
      const response = await createDemoServer({ persona: "admin" }).handle("GET", "/api/v1/settings");
      expect(response.status).toBe(200);
      const body = await json(response);
      expect((body.items as { value: unknown }[]).map((i) => i.value)).toEqual([false, 90]);
      expect(body.recent).toEqual([]);
    } finally { vi.unstubAllGlobals(); }
  });
});
