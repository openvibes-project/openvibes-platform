// The demo's port page answers like GET /api/v1/ports/{protocol}/{port}/summary
// and /hosts (ports/page.rs, platform-store port_summary.rs): path and query
// validation, the header and tiles agree with the list, the segments add up,
// and the Related card and actions follow the persona's permissions.
import { describe, expect, it } from "vitest";

import type { PortList, PortPageHosts, PortPageSummary } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

const get = async <T>(path: string, persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", path, undefined);
  return { status: response.status, body: (await response.json()) as T & { code?: string; field_errors?: { field: string }[] } };
};
const summary = (key: string, persona?: Persona) => get<PortPageSummary>(`/api/v1/ports/${key}/summary`, persona);

describe("demo port page", () => {
  it.each(["icmp/22", "tcp/0", "tcp/65536", "tcp/022", "tcp/ssh"])("refuses %s", async (key) => {
    for (const tail of ["summary", "hosts"]) {
      const { status, body } = await get(`/api/v1/ports/${key}/${tail}`);
      expect([status, body.code]).toEqual([400, "invalid_port"]);
    }
  });

  it("answers 404 for a port nothing listens on", async () => {
    const { status, body } = await summary("tcp/4444");
    expect([status, body.code]).toEqual([404, "port_not_found"]);
  });

  it("agrees with the list on hosts and exposure", async () => {
    const list = (await get<PortList>("/api/v1/port-list?limit=100")).body;
    for (const row of list.items.slice(0, 8)) {
      const { status, body } = await summary(`${row.protocol}/${row.port}`);
      expect(status).toBe(200);
      expect(body.tiles).toMatchObject({ listening: row.hosts, exposed: row.exposed_hosts, local: row.hosts - row.exposed_hosts });
      expect(body.tiles.week).toEqual({ added: row.week_added, removed: row.week_removed });
    }
    const ssh = (await summary("tcp/22")).body;
    expect(ssh.header).toMatchObject({ name: "SSH", protocol: "tcp", port: 22 });
  });

  it("lists the hosts in segments that add up", async () => {
    const all = (await get<PortPageHosts>("/api/v1/ports/tcp/22/hosts")).body;
    expect(all.segments.exposed + all.segments.local).toBe(all.segments.all);
    expect(all.total).toBe(all.segments.all);
    for (const segment of ["exposed", "local"] as const) {
      const part = (await get<PortPageHosts>(`/api/v1/ports/tcp/22/hosts?segment=${segment}`)).body;
      expect(part.total).toBe(all.segments[segment]);
      expect(part.items.every((h) => h.exposed === (segment === "exposed"))).toBe(true);
    }
    const page = (await get<PortPageHosts>("/api/v1/ports/tcp/22/hosts?limit=1&offset=1")).body;
    expect([page.items.length, page.total]).toEqual([Math.min(1, Math.max(0, all.total - 1)), all.total]);
  });

  it.each([["segment=gone", "segment"], ["offset=-1", "offset"], ["surprise=1", "query"]])("refuses %s", async (query, field) => {
    const { status, body } = await get(`/api/v1/ports/tcp/22/hosts?${query}`);
    expect([status, body.field_errors?.[0]?.field]).toEqual([400, field]);
  });

  it("refuses a limit outside 1 to 100", async () => {
    for (const limit of ["0", "101"]) expect((await get(`/api/v1/ports/tcp/22/hosts?limit=${limit}`)).status).toBe(400);
  });

  it("offers the admin every action and every Related section", async () => {
    const { body } = await summary("tcp/22");
    expect(body.can.export).toBe(true);
    expect(Object.keys(body.related).sort()).toEqual(["alarms", "compliance", "vulnerabilities"]);
  });
});
