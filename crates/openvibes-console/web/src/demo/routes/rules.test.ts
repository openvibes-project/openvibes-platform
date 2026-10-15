import { describe, expect, it } from "vitest";

import { createDemoServer } from "../server";

async function json(response: Response) {
  return response.json() as Promise<Record<string, unknown>>;
}

describe("demo rules", () => {
  it("previews a signed bundle and publishes it with the preview token", async () => {
    const server = createDemoServer({ persona: "admin" });
    const envelope = { rule_set_id: "site", rule_set_version: 99, issuer_key_id: "ops-2026", expires_at_unix_ms: Date.now() + 86_400_000 };
    const preview = await json(await server.handle("POST", "/api/v1/rule-bundles/preview", envelope));
    expect(preview.version).toBe(99);
    expect((await server.handle("POST", "/api/v1/rule-bundles/publish", envelope)).status).toBe(428);
    const published = await server.handle("POST", "/api/v1/rule-bundles/publish", envelope, { "x-rule-preview-token": String(preview.preview_token) });
    expect(published.status).toBe(201);
    const sets = await json(await server.handle("GET", "/api/v1/rule-sets"));
    expect((sets.items as { rule_set_id: string; current_version: number }[]).find((set) => set.rule_set_id === "site")?.current_version).toBe(99);
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
});
