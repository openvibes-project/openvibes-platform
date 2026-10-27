// The demo's Ports list answers like GET /api/v1/port-list (ports/list_page.rs,
// platform-store port_list.rs): validation, one row per port, counts with the
// other filters applied, the summary, Needs a look and reach.
import { describe, expect, it } from "vitest";

import type { PortList } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Body = PortList & { field_errors?: { field: string }[] };
const URL = "/api/v1/port-list";
const get = async (query = "", persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", `${URL}${query ? `?${query}` : ""}`, undefined);
  return { status: response.status, body: (await response.json()) as Body };
};
const keys = (b: PortList) => b.items.map((i) => `${i.protocol}/${i.port}`);
const n = (counts: { value: string; count: number }[], value: string) => counts.find((c) => c.value === value)?.count;
const row = (b: PortList, key: string) => b.items.find((i) => `${i.protocol}/${i.port}` === key);

describe("demo Ports list", () => {
  it.each([
    ["exposure=gone", "exposure"], ["protocol=icmp", "protocol"], ["changes=old", "changes"], ["group=!", "group"], ["host=%00", "host"],
    ["service=%00", "service"], ["sort=colour", "sort"], ["dir=up", "dir"], ["offset=-1", "offset"], ["offset=100001", "offset"],
    [`q=${"x".repeat(201)}`, "q"], ["exposed=true", "query"],
  ])("refuses %s naming %s", async (query, field) => {
    const { status, body } = await get(query);
    expect(status).toBe(400);
    expect(body.field_errors?.[0]?.field).toBe(field);
  });

  it("refuses a limit outside 1 to 100", async () => {
    for (const limit of ["0", "101"]) expect((await get(`limit=${limit}`)).status).toBe(400);
  });

  it("lists one row per port by number, with names, host counts and services", async () => {
    const { body } = await get("limit=100");
    const k = keys(body);
    expect(new Set(k).size).toBe(k.length);
    expect(k).toEqual([...k].sort((a, b) => Number(a.split("/")[1]) - Number(b.split("/")[1]) || a.localeCompare(b)));
    expect(body.total).toBe(k.length);
    const ssh = row(body, "tcp/22");
    expect(ssh).toMatchObject({ name: "SSH", services: ["sshd.service"], owners_missing: false });
    expect(ssh?.hosts).toBe(body.summary.reporting_hosts);
    expect(row(body, "tcp/8888")).toMatchObject({ owners_missing: true });
    expect(row(body, "tcp/8888")?.name).toBeUndefined();
    expect(row(body, "udp/53")?.exposed_hosts).toBeGreaterThan(0);
  });

  it("covers every filter: a local-only port, a database exposed, a new unusual port, an owner not collected", async () => {
    const all = (await get("limit=100")).body;
    expect(row(all, "udp/1194")?.look).toEqual(["new_unusual"]);
    expect(row(all, "tcp/5432")?.look).toEqual(["database_exposed"]);
    expect(row(all, "tcp/3389")?.look).toEqual(["remote_admin_exposed"]);
    expect(row(all, "tcp/22")?.look).toEqual([]);
    const local = (await get("exposure=local&limit=100")).body;
    expect(local.total).toBeGreaterThan(0);
    expect(local.items.every((r) => r.exposed_hosts === 0)).toBe(true);
    const fresh = (await get("changes=new&limit=100")).body;
    expect(keys(fresh)).toEqual(expect.arrayContaining(["udp/1194", "tcp/8888", "tcp/3389", "tcp/443"]));
    expect(keys(fresh)).not.toContain("tcp/5432");
    expect(n(all.counts.changes, "new")).toBe(fresh.total);
    expect(keys((await get("changes=look&limit=100")).body)).toEqual(expect.arrayContaining(["udp/1194", "tcp/5432", "tcp/3389"]));
    expect(keys((await get("service=~none")).body)).toEqual(["tcp/8888"]);
    expect(keys((await get("service=nginx.service&limit=100")).body)).toEqual(["tcp/80", "tcp/443"]);
    expect(keys((await get("protocol=udp&limit=100")).body)).toEqual(expect.arrayContaining(["udp/53", "udp/1194"]));
    expect((await get("protocol=udp&limit=100")).body.items.every((r) => r.protocol === "udp")).toBe(true);
  });

  it("counts every value with the other filters applied", async () => {
    const udp = (await get("protocol=udp&limit=100")).body;
    expect(n(udp.counts.protocol, "tcp")).toBe((await get("limit=100")).body.total - udp.total);
    expect((n(udp.counts.exposure, "exposed") ?? 0) + (n(udp.counts.exposure, "local") ?? 0)).toBe(udp.total);
    const search = (await get("q=postgres")).body;
    expect(keys(search)).toEqual(["tcp/5432"]);
    expect(keys((await get("q=22%2Ftcp")).body)).toEqual(["tcp/22"]);
    expect(keys((await get("q=redis.service")).body)).toEqual(["tcp/6379"]);
    expect(keys((await get("q=remote%20desktop")).body)).toEqual(expect.arrayContaining(["tcp/3389"]));
  });

  it("sums the summary over the matching rows and pages stably", async () => {
    const all = (await get("limit=100")).body;
    expect(all.summary.exposed).toBe(all.items.filter((r) => r.exposed_hosts > 0).length);
    expect(all.summary.need_a_look).toBe(all.items.filter((r) => r.look.length > 0).length);
    const seen: string[] = [];
    for (let offset = 0; offset < all.total; offset += 4) seen.push(...keys((await get(`limit=4&offset=${offset}`)).body));
    expect(seen).toEqual(keys(all));
    const byHosts = (await get("sort=hosts&dir=desc&limit=100")).body;
    expect(byHosts.items.map((r) => r.hosts)).toEqual([...byHosts.items.map((r) => r.hosts)].sort((a, b) => b - a));
    const byWeek = (await get("sort=week&dir=desc&limit=100")).body;
    expect(byWeek.items[0]?.week_added).toBeGreaterThan(0);
    expect(row(all, "tcp/80")?.week_removed).toBe(1);
  });

  it("keeps a team lead to their group's hosts", async () => {
    const global = (await get("limit=100")).body;
    const lead = (await get("limit=100", "team_lead")).body;
    expect(lead.total).toBeLessThan(global.total);
    expect(lead.summary.reporting_hosts).toBeLessThan(global.summary.reporting_hosts);
    expect(lead.counts.group.every((g) => global.counts.group.some((x) => x.value === g.value))).toBe(true);
  });
});
