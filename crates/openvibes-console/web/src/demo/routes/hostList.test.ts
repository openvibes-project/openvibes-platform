// The demo's Hosts list answers like GET /api/v1/hosts (hosts/list.rs):
// validation, the alarms-off warning, search by agent id, chosen values.
import { describe, expect, it } from "vitest";

import type { HostList } from "../../api/types";
import { createDemoServer } from "../server";

const get = async (path: string, persona: "admin" | "scoped_operator" = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", path, undefined);
  return { status: response.status, body: (await response.json()) as HostList & { field_errors?: { field: string }[] } };
};

describe("demo Hosts list", () => {
  it.each([
    ["group=not-a-group-id!", "group"], [`q=${"x".repeat(201)}`, "q"], [`label=${"l".repeat(65)}`, "label"],
    ["problems=open_alarms", "problems"], ["sort=enrolled", "sort"],
  ])("refuses %s naming %s", async (query, field) => {
    const { status, body } = await get(`/api/v1/hosts?${query}`);
    expect(status).toBe(400);
    expect(body.field_errors?.[0]?.field).toBe(field);
  });

  it("warns only of online hosts whose alarms are off by a fault", async () => {
    const { body } = await get("/api/v1/hosts?limit=100&q=agent-00");
    const all = [...body.items, ...(await get("/api/v1/hosts?limit=100&offset=100&q=agent-00")).body.items];
    const off = all.filter((h) => h.alarms_off).map((h) => h.id);
    expect(off.length).toBeGreaterThan(0);
    // agent-00023 is off by a fault, agent-00029 only not enabled (demo data).
    expect(off).not.toContain("agent-00029");
    for (const h of all.filter((h) => h.alarms_off)) expect(h.status).toBe("online");
  });

  it("finds a host by its agent id or an id prefix", async () => {
    expect((await get("/api/v1/hosts?q=agent-00005")).body.items.map((h) => h.id)).toEqual(["agent-00005"]);
    expect((await get("/api/v1/hosts?q=AGENT-0001")).body.total).toBe(10);
  });

  it("lists problems counts in the URL spelling and a chosen label with none in place", async () => {
    const { body } = await get("/api/v1/hosts?label=kiosk&status=revoked");
    expect(body.counts.problems.map((c) => c.value)).toEqual(["critical", "alarms", "none"]);
    expect(body.counts.label.map((c) => c.value)).toContain("kiosk");
    expect(body.counts.label.at(-1)).toEqual({ value: "kiosk", count: 0 });
  });

  it("leaves a host silent for a day out of none open, its failing count unknown", async () => {
    const all = (await get("/api/v1/hosts?limit=100")).body;
    const rest = (await get("/api/v1/hosts?limit=100&offset=100")).body.items;
    const items = [...all.items, ...rest];
    const stale = items.filter((h) => h.problems.compliance_stale);
    expect(stale.length).toBeGreaterThan(0);
    for (const h of stale) expect(h.problems.failing).toBeNull();
    const none = (await get("/api/v1/hosts?problems=none&limit=100")).body.items.map((h) => h.id);
    for (const h of stale) expect(none).not.toContain(h.id);
  });
});
