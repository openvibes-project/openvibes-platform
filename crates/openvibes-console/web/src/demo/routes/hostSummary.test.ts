// The demo's host summary answers like GET /api/v1/hosts/{id}/summary
// (hosts/summary.rs): each section only where its permission reaches.
import { describe, expect, it } from "vitest";

import type { HostSummary } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

const get = async (id: string, persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", `/api/v1/hosts/${id}/summary`, undefined);
  return { status: response.status, body: (await response.json()) as HostSummary & { code?: string } };
};

describe("demo host summary", () => {
  it("answers the header facts, tiles and top three of a host", async () => {
    const { status, body } = await get("agent-00005");
    expect(status).toBe(200);
    expect(body.host.id).toBe("agent-00005");
    expect(body.host.os.distribution).toMatch(/^[A-Z]/);
    expect(body.tiles.software).toBe(body.inventory.packages);
    expect(body.tiles.open_alarms).toBe(body.top_alarms?.total);
    expect(body.tiles.vulnerabilities).toBe(body.top_vulnerabilities?.total);
    expect(body.tiles.compliance_failing).toBe(body.top_failing?.total);
    expect(body.top_vulnerabilities?.items.length).toBeLessThanOrEqual(3);
    expect(body.inventory.listening_ports).toBeGreaterThan(0);
    expect(body.certificates.length).toBeLessThanOrEqual(5);
    expect(body.can).toEqual({ label: true, revoke: true, export: true, add_to_case: true, ask: true });
  });

  it("leaves out what the persona cannot read: no alarms without alarms.read", async () => {
    const { body } = await get("agent-00005", "rule_author");
    expect(body.tiles.open_alarms ?? null).toBeNull();
    expect(body.top_alarms ?? null).toBeNull();
    expect(body.top_vulnerabilities ?? null).toBeNull();
    expect(body.top_failing ?? null).toBeNull();
    expect(body.tiles.software).toBeGreaterThan(0);
    expect(body.can).toEqual({ label: false, revoke: false, export: false, add_to_case: false, ask: false });
  });

  it("is 404 host_not_found for a host out of reach or unknown", async () => {
    expect((await get("agent-99999")).body.code).toBe("host_not_found");
    const outside = await get("agent-00001", "scoped_operator");
    const listed = (await (await createDemoServer({ persona: "scoped_operator" }).handle("GET", "/api/v1/agents?limit=100", undefined)).json()) as { items: { id: string }[] };
    expect(outside.status).toBe(listed.items.some((a) => a.id === "agent-00001") ? 200 : 404);
  });

  it("offers no label or revoke on a revoked host", async () => {
    const server = createDemoServer();
    const agents = (await (await server.handle("GET", "/api/v1/agents?state=revoked&limit=1", undefined)).json()) as { items: { id: string }[] };
    const id = agents.items[0]?.id ?? "";
    const body = (await (await server.handle("GET", `/api/v1/hosts/${id}/summary`, undefined)).json()) as HostSummary;
    expect(body.host.status).toBe("revoked");
    expect(body.can.label).toBe(false);
    expect(body.can.revoke).toBe(false);
  });

  it("counts what the lists show by default: a triaged advisory or check leaves the tile, the list and the Compliance view", async () => {
    const server = createDemoServer();
    const call = async (method: string, path: string, body?: unknown) => (await server.handle(method, path, body)).json() as Promise<Record<string, unknown>>;
    const before = (await call("GET", "/api/v1/hosts/agent-00005/summary")) as unknown as HostSummary;
    const advisory = before.top_vulnerabilities?.items[0]?.advisory ?? "";
    const check = before.top_failing?.items[0];
    expect(advisory).not.toBe("");
    expect(check).toBeDefined();
    await call("POST", "/api/v1/vulnerabilities/bulk", { action: "state", state: "accepted_risk", note: "later", accepted_until: new Date(Date.now() + 86_400_000 * 30).toISOString(), items: [{ advisory_id: advisory, agent_id: "agent-00005" }] });
    await call("POST", "/api/v1/compliance/bulk", { action: "state", state: "mitigated", note: "patched", items: [{ rule_set_id: check?.rule_set_id, rule_id: check?.rule_id, agent_id: "agent-00005" }] });
    const after = (await call("GET", "/api/v1/hosts/agent-00005/summary")) as unknown as HostSummary;
    expect(after.tiles.vulnerabilities).toBe((before.tiles.vulnerabilities ?? 0) - 1);
    expect(after.top_vulnerabilities?.items.map((v) => v.advisory)).not.toContain(advisory);
    expect(after.tiles.compliance_failing).toBe((before.tiles.compliance_failing ?? 0) - 1);
    const row = ((await call("GET", "/api/v1/hosts?q=agent-00005")).items as { problems: { failing: number } }[])[0];
    expect(row?.problems.failing).toBe(after.tiles.compliance_failing);
    const groups = (await call("GET", "/api/v1/compliance/groups?agent_id=agent-00005")).items as { rule_id: string; endpoint_count: number; triage_counts: { open: number } }[];
    expect(groups.every((g) => g.endpoint_count === 1)).toBe(true);
    expect(groups.filter((g) => g.triage_counts.open > 0)).toHaveLength(after.tiles.compliance_failing ?? -1);
  });

  it("the Hosts list counts critical advisories as the page lists them: an accepted risk leaves the count", async () => {
    const server = createDemoServer();
    const call = async (method: string, path: string, body?: unknown) => (await server.handle(method, path, body)).json() as Promise<Record<string, unknown>>;
    const critical = async (id: string) => ((await call("GET", `/api/v1/hosts?q=${id}`)).items as { problems: { critical: number } }[])[0]?.problems.critical ?? -1;
    const vulns = (await call("GET", "/api/v1/vulnerabilities")).items as { agent_id: string; advisory_id: string; severity: string }[];
    const hit = vulns.find((v) => v.severity === "critical");
    expect(hit).toBeDefined();
    const id = hit?.agent_id ?? "";
    const before = await critical(id);
    expect(before).toBeGreaterThan(0);
    await call("POST", "/api/v1/vulnerabilities/bulk", { action: "state", state: "accepted_risk", note: "later", accepted_until: new Date(Date.now() + 86_400_000 * 30).toISOString(), items: [{ advisory_id: hit?.advisory_id, agent_id: id }] });
    expect(await critical(id)).toBe(before - 1);
  });
  it("counts failing as the Compliance list does, and says when a host has not reported for a day (roles 5c)", async () => {
    const server = createDemoServer();
    const call = async (path: string) => (await server.handle("GET", path, undefined)).json() as Promise<Record<string, unknown>>;
    const hosts = (await call("/api/v1/hosts?limit=100")).items as { id: string; last_seen_at: string | null; problems: { failing: number | null } }[];
    for (const id of ["agent-00001", "agent-00002", "agent-00005"]) {
      const summary = (await call(`/api/v1/hosts/${id}/summary`)) as unknown as HostSummary;
      const list = (await call(`/api/v1/compliance-list?host=${id}&limit=100`)).items as { rule_id: string; open: number }[];
      // The tile, the Hosts list and /compliance?host= count the same open failing checks.
      expect(summary.tiles.compliance_failing).toBe(list.filter((r) => r.open > 0).length);
      const row = ((await call(`/api/v1/hosts?q=${id}`)).items as { problems: { failing: number | null } }[])[0];
      expect(row?.problems.failing).toBe(summary.tiles.compliance_failing);
      expect(summary.tiles.compliance_stale).toBe(false);
    }
    // agent-00002's acceptance of empty SSH passwords expired: open again.
    const two = (await call("/api/v1/hosts/agent-00002/summary")) as unknown as HostSummary;
    expect((await call("/api/v1/compliance-list?host=agent-00002&q=permit_empty_passwords")).total).toBe(1);
    expect(two.tiles.compliance_failing).toBeGreaterThan(0);
    const silent = hosts.find((h) => h.last_seen_at !== null && Date.parse(h.last_seen_at) < Date.now() - 86_400_000);
    expect(silent).toBeDefined();
    const stale = (await call(`/api/v1/hosts/${silent?.id ?? ""}/summary`)) as unknown as HostSummary;
    expect(stale.tiles.compliance_stale).toBe(true);
    expect(stale.tiles.compliance_failing).toBe(0);
  });
});
