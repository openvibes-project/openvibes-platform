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
    expect(permissions).toEqual(["agents.read", "findings.read", "vulnerabilities.read"]);
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
    const groups = await json(await server.handle("GET", "/api/v1/findings/groups?limit=100"));
    const group = (groups.items as { rule_set_id: string; rule_id: string; endpoint_count: number }[])[0];
    if (group === undefined) throw new Error("no groups");
    const endpoints = await json(await server.handle("GET", `/api/v1/findings/groups/${group.rule_set_id}/${group.rule_id}/endpoints?limit=100`));
    const changes = (endpoints.items as { agent_id: string; triage_version: number }[]).map((e) => ({ agent_id: e.agent_id, version: e.triage_version }));
    const response = await server.handle("POST", `/api/v1/findings/groups/${group.rule_set_id}/${group.rule_id}/triage`, { state: "mitigated", changes });
    expect(response.status).toBe(200);
    const after = await json(await server.handle("GET", "/api/v1/findings/groups?limit=100"));
    const updated = (after.items as { rule_id: string; triage_counts: { mitigated: number } }[]).find((g) => g.rule_id === group.rule_id);
    expect(updated?.triage_counts.mitigated).toBe(group.endpoint_count);
    const audit = await json(await server.handle("GET", `/api/v1/audit-events?limit=1&since=${new Date(Date.now() - 86_400_000).toISOString()}`));
    expect((audit.items as { action: string }[])[0]?.action).toBe("finding.triage");
  });

  it("rejects a stale triage version with 409", async () => {
    const server = createDemoServer({ persona: "admin" });
    const groups = await json(await server.handle("GET", "/api/v1/findings/groups?limit=1"));
    const group = (groups.items as { rule_set_id: string; rule_id: string }[])[0];
    if (group === undefined) throw new Error("no groups");
    const endpoints = await json(await server.handle("GET", `/api/v1/findings/groups/${group.rule_set_id}/${group.rule_id}/endpoints?limit=1`));
    const endpoint = (endpoints.items as { agent_id: string }[])[0];
    const response = await server.handle("POST", `/api/v1/findings/groups/${group.rule_set_id}/${group.rule_id}/triage`, { state: "mitigated", changes: [{ agent_id: endpoint?.agent_id, version: 99 }] });
    expect(response.status).toBe(409);
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
    expect((await server.handle("GET", "/api/v1/findings/groups?limit=250")).status).toBe(400);
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

  it("answers 404 for unknown routes", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await server.handle("GET", "/api/v1/nope")).status).toBe(404);
  });
});
