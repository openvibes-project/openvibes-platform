// Hosts (agents), their tags, and enrolling new ones.
import type { Agent } from "../../api/types";
import type { DemoContext } from "../context";
import { json, page, problem } from "../http";

export function registerHostRoutes(ctx: DemoContext) {
  const { data, iso, visible, agentById, audit, route } = ctx;
  route("GET", "/api/v1/agents", "hosts.read", (_, query) => {
    const state = query.get("state");
    const items = data.agents.filter((agent) => visible(agent.id) && (state === null || agent.status === state));
    return json({ ...page(items, query), generated_at: iso() });
  });
  route("GET", "/api/v1/agents/summary", "hosts.read", () => {
    const items = data.agents.filter((agent) => visible(agent.id));
    const count = (status: Agent["status"]) => items.filter((agent) => agent.status === status).length;
    // The demo fleet's newest agents run the demo platform's version.
    return json({ total: items.length, active: count("active"), stale: count("stale"), revoked: count("revoked"), imported: count("imported"), platform_version: "0.4.2" });
  });
  route("GET", "/api/v1/agents/{id}", "hosts.read", ({ id = "" }) => {
    const agent = agentById(id);
    return agent ? json({ ...agent, certificates: data.certificates.get(id) ?? [], last_test: { alarm_at: agent.id.endsWith("1") ? new Date(Date.now() - 120_000).toISOString() : null, finding_at: null } }) : problem(404, "not_found", "Agent not found");
  });
  route("GET", "/api/v1/agents/{id}/certificates", "hosts.read", ({ id = "" }, query) =>
    json({ ...page(data.certificates.get(id) ?? [], query), generated_at: iso() }));
  route("POST", "/api/v1/agents/{id}/revoke", "hosts.revoke", ({ id = "" }, _, body) => {
    const agent = agentById(id);
    if (!agent) return problem(404, "not_found", "Agent not found");
    if (String(body.reason ?? "").trim() === "") return problem(422, "invalid_reason", "A reason is required");
    agent.status = "revoked";
    agent.revoked_at = iso();
    audit("agent.revoke", id, "agent");
    return json(agent);
  });
  route("POST", "/api/v1/agents/{id}/tags/preview", "host_groups.manage", ({ id = "" }, _, body) => json({
    current: data.tags.get(id) ?? [], proposed: body.tags ?? [], preview_token: `preview-${id}`,
    gained_groups: [], lost_groups: [], gained_bindings: [], lost_bindings: [],
  }));
  route("PUT", "/api/v1/agents/{id}/tags", "host_groups.manage", ({ id = "" }, _, body) => {
    data.tags.set(id, (body.tags ?? []) as { key: string; value: string }[]);
    audit("agent.tags.update", id, "agent");
    return json({ tags: data.tags.get(id) });
  });

  route("GET", "/api/v1/enrollment-tokens", "tokens.read", () => json({ items: data.enrollmentTokens }));
  // The real command carries the platform's standing token; the demo's is made up.
  route("GET", "/api/v1/agent-command", "tokens.installer", () => json({
    command: "curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh -s -- --agent --platform platform.example.com --token DEMO-standing-token-not-real --ca-sha256 4F:2A:9C:11:D3:7E:58:B0:6A:C4:22:91:EE:03:7B:5D:A8:16:F0:3C:94:BB:2E:61:0D:7A:C9:55:18:E4:A3:F2",
  }));
  const idempotent = new Map<string, { token_id: string; expires_at: string }>();
  route("POST", "/api/v1/enrollment-tokens", "tokens.manage", (_, __, body, headers) => {
    const key = headers["idempotency-key"] ?? "";
    if (!/^[\x21-\x7e]{16,128}$/.test(key)) return problem(400, "invalid_idempotency_key", "Provide an Idempotency-Key header between 16 and 128 visible ASCII characters");
    const previous = idempotent.get(key);
    if (previous) return json({ ...previous, secret_available: false, replayed: true });
    const token_id = `tok-${Date.now().toString(16).slice(-4)}${idempotent.size}`;
    const expires = iso(Date.now() + Number(body.expires_in_hours ?? 24) * 3_600_000);
    idempotent.set(key, { token_id, expires_at: expires });
    data.enrollmentTokens.unshift({ token_id, label: (body.label as string | null) ?? null, created_at: iso(), expires_at: expires, max_uses: Number(body.max_uses ?? 1), uses: 0, revoked: false, standing: false });
    audit("enrollment_token.create", token_id, "enrollment_token");
    return json({ token_id, token: `ovet_demo_${crypto.randomUUID().replaceAll("-", "")}`, expires_at: expires, secret_available: true, replayed: false }, 201);
  });
  route("POST", "/api/v1/enrollment-tokens/{id}/revoke", "tokens.manage", ({ id = "" }) => {
    const token = data.enrollmentTokens.find((t) => t.token_id === id);
    if (!token) return problem(404, "not_found", "Token not found");
    token.revoked = true;
    audit("enrollment_token.revoke", id, "enrollment_token");
    return json(token);
  });
}
