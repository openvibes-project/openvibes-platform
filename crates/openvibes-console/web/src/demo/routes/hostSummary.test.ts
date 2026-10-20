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
});
