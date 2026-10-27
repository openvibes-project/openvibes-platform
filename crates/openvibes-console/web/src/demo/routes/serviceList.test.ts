// The demo's Services list answers like GET /api/v1/service-list
// (services/list_page.rs, platform-store service_list.rs): validation, one
// row per unit, counts with the other filters applied, the summary, Needs a
// look and reach.
import { describe, expect, it } from "vitest";

import type { ServiceList } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Body = ServiceList & { field_errors?: { field: string }[] };
const URL = "/api/v1/service-list";
const get = async (query = "", persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", `${URL}${query ? `?${query}` : ""}`, undefined);
  return { status: response.status, body: (await response.json()) as Body };
};
const units = (b: ServiceList) => b.items.map((i) => i.unit);
const n = (counts: { value: string; count: number }[], value: string) => counts.find((c) => c.value === value)?.count;

describe("demo Services list", () => {
  it.each([
    ["runs_as=nobody", "runs_as"], ["listens=maybe", "listens"], ["packaged=sometimes", "packaged"], ["changes=old", "changes"], ["group=!", "group"], ["host=%00", "host"],
    ["sort=colour", "sort"], ["dir=up", "dir"], ["offset=-1", "offset"], [`q=${"x".repeat(201)}`, "q"], ["exposed=true", "query"],
  ])("refuses %s naming %s", async (query, field) => {
    const { status, body } = await get(query);
    expect(status).toBe(400);
    expect(body.field_errors?.[0]?.field).toBe(field);
  });

  it("lists one row per unit by name, with usual names and host counts", async () => {
    const { body } = await get("limit=100");
    const u = units(body);
    expect(new Set(u).size).toBe(u.length);
    expect(u).toEqual([...u].sort());
    expect(body.total).toBe(u.length);
    const ssh = body.items.find((i) => i.unit === "sshd.service");
    expect(ssh).toMatchObject({ name: "OpenSSH server", usual_use: "Secure remote login" });
    expect(ssh?.hosts).toBeGreaterThan(1);
    expect(ssh?.ports.some((p) => p.port === 22 && p.exposed)).toBe(true);
  });

  it("tells root from other users", async () => {
    const root = (await get("runs_as=root&limit=100")).body;
    const other = (await get("runs_as=other&limit=100")).body;
    expect(units(root)).toContain("sshd.service");
    expect(units(other)).toContain("postgresql.service");
    expect(units(root).filter((u) => units(other).includes(u))).toEqual([]);
    expect(root.total + other.total).toBe((await get()).body.total);
  });

  it("counts each filter value with the other filters applied", async () => {
    const all = (await get("limit=100")).body;
    expect(all.counts.runs_as.reduce((sum, c) => sum + c.count, 0)).toBe(all.total);
    const exposed = (await get("listens=exposed&limit=100")).body;
    expect(exposed.total).toBe(n(all.counts.listens, "exposed"));
    expect(n(exposed.counts.runs_as, "root")).toBe(exposed.items.filter((i) => i.root_hosts > 0).length);
    expect(exposed.summary.exposed).toBe(exposed.total);
  });

  it("flags the units that need a look", async () => {
    const { body } = await get("changes=look&limit=100");
    expect(body.total).toBeGreaterThan(0);
    expect(body.items.every((i) => i.look.length > 0)).toBe(true);
    expect(body.summary.need_a_look).toBe(body.total);
  });

  it("searches by unit, usual name and program", async () => {
    expect(units((await get("q=openssh")).body)).toContain("sshd.service");
    expect(units((await get("q=nginx")).body)).toContain("nginx.service");
    expect((await get("q=zzzz")).body.total).toBe(0);
  });

  it("sorts and pages", async () => {
    const byHosts = (await get("sort=hosts&dir=desc&limit=100")).body;
    expect(byHosts.items.map((i) => i.hosts)).toEqual([...byHosts.items.map((i) => i.hosts)].sort((a, b) => b - a));
    const second = (await get("limit=2&offset=2")).body;
    expect(second.items).toHaveLength(2);
    expect(units(second)).toEqual(units((await get("limit=100")).body).slice(2, 4));
  });

  it("answers within the scoped operator's reach", async () => {
    const full = (await get("")).body;
    const scoped = (await get("", "scoped_operator")).body;
    expect(scoped.total).toBeLessThanOrEqual(full.total);
    expect(scoped.summary.reporting_hosts).toBeLessThan(full.summary.reporting_hosts);
  });
});
