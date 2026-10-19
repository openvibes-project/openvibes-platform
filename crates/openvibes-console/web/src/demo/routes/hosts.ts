// Hosts (agents), their labels, and enrolling new ones.
import type { Agent } from "../../api/types";
import type { DemoContext } from "../context";
import { hasControl, inGroup, isActive } from "../hostGroups";
import { json, page, problem } from "../http";

const MAX_LABELS = 32;

/**
 * Host labels (hosts/labels.rs, store host_labels.rs): read with hosts.read,
 * changed with hosts.label on the host; a host out of reach is 404 like a
 * missing one. Labels never change groups or access.
 */
function registerLabelRoutes(ctx: DemoContext) {
  const { data, audit, route, reaches, facts } = ctx;
  const notFound = () => problem(404, "host_not_found", "No such host");
  const reachable = (permission: "hosts.read" | "hosts.label", id: string) =>
    data.agents.find((a) => a.id === id && a.status !== "revoked" && reaches(permission, id));
  const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  route("GET", "/api/v1/hosts/{id}/labels", "hosts.read", ({ id = "" }) => {
    const agent = reachable("hosts.read", id);
    if (!agent) return notFound();
    const groups = data.access.host_groups.filter((g) => inGroup(facts(agent), g)).sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()))
      .map((g) => ({ asset_group_id: g.asset_group_id, name: g.name, kind: g.kind }));
    return json({ labels: [...(data.labels.get(id) ?? [])].sort(byteOrder), groups });
  });
  route("PUT", "/api/v1/hosts/{id}/labels/{label}", "hosts.label", ({ id = "", label = "" }) => {
    const agent = reachable("hosts.label", id);
    if (!agent) return notFound();
    const text = label.trim();
    if ([...text].length < 1 || [...text].length > 64 || hasControl(text)) return problem(400, "invalid_label", "Use 1 to 64 characters, without control characters");
    if (!isActive(agent)) return notFound();
    const labels = data.labels.get(id) ?? [];
    if (labels.includes(text)) return new Response(null, { status: 204 });
    if (labels.length >= MAX_LABELS) return problem(409, "too_many_labels", "A host has at most 32 labels");
    data.labels.set(id, [...labels, text]);
    audit("host.label_added", id, "agent");
    return new Response(null, { status: 204 });
  });
  route("DELETE", "/api/v1/hosts/{id}/labels/{label}", "hosts.label", ({ id = "", label = "" }) => {
    if (!reachable("hosts.label", id)) return notFound();
    const labels = data.labels.get(id) ?? [];
    if (labels.includes(label.trim())) {
      data.labels.set(id, labels.filter((l) => l !== label.trim()));
      audit("host.label_removed", id, "agent");
    }
    return new Response(null, { status: 204 });
  });
}

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
  registerLabelRoutes(ctx);

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
