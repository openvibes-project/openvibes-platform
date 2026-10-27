// The demo's service page answers like GET /api/v1/services/{unit}/summary
// and /hosts (services/page.rs, platform-store service_summary.rs): path and
// query validation, the header and tiles agree with the list, the segments
// add up, and the Related card and actions follow the persona's permissions.
import { describe, expect, it } from "vitest";

import type { ServiceList, ServicePageHosts, ServicePageSummary } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

const get = async <T>(path: string, persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", path, undefined);
  return { status: response.status, body: (await response.json()) as T & { code?: string; field_errors?: { field: string }[] } };
};
const summary = (unit: string, persona?: Persona) => get<ServicePageSummary>(`/api/v1/services/${encodeURIComponent(unit)}/summary`, persona);
const hosts = (unit: string, query = "") => get<ServicePageHosts>(`/api/v1/services/${encodeURIComponent(unit)}/hosts${query}`);

describe("demo service page", () => {
  it("refuses an over-long or control-character unit", async () => {
    for (const unit of ["x".repeat(201), "a%00b"]) {
      for (const tail of ["summary", "hosts"]) {
        const { status, body } = await get(`/api/v1/services/${unit}/${tail}`);
        expect([status, body.code]).toEqual([400, "invalid_unit"]);
      }
    }
  });

  it("answers 404 for a unit no host runs", async () => {
    const { status, body } = await summary("nothing.service");
    expect([status, body.code]).toEqual([404, "service_not_found"]);
  });

  it("agrees with the list on hosts, root, exposure and week", async () => {
    const list = (await get<ServiceList>("/api/v1/service-list?limit=100")).body;
    for (const row of list.items.slice(0, 8)) {
      const { status, body } = await summary(row.unit);
      expect(status).toBe(200);
      expect(body.header).toMatchObject({ unit: row.unit, running: row.hosts, root: row.root_hosts, exposed: row.exposed_hosts });
      expect(body.details.week).toEqual({ added: row.week_added, removed: row.week_removed });
      expect(body.details.package_hosts).toBe(row.package_hosts);
    }
    const ssh = (await summary("sshd.service")).body;
    expect(ssh.header).toMatchObject({ name: "OpenSSH server", unit: "sshd.service" });
    expect(ssh.ports.some((p) => p.port === 22 && p.exposed)).toBe(true);
  });

  it("splits its hosts into segments that add up", async () => {
    const all = (await hosts("sshd.service")).body;
    expect(all.segments.all).toBe(all.total);
    const exposed = (await hosts("sshd.service", "?segment=exposed")).body;
    const root = (await hosts("sshd.service", "?segment=root")).body;
    expect([exposed.total, root.total]).toEqual([all.segments.exposed, all.segments.root]);
    expect(root.items.every((h) => h.run_as === "root")).toBe(true);
    expect((await hosts("sshd.service", "?segment=bogus")).status).toBe(400);
    expect((await hosts("sshd.service", "?limit=1&offset=1")).body.items).toHaveLength(1);
  });

  it("keeps a unit that went away viewable and follows the persona's permissions", async () => {
    const admin = (await summary("postgresql.service")).body;
    expect(admin.can.add_to_case).toBe(true);
    expect(admin.related.alarms).toBeDefined();
    const viewer = (await summary("postgresql.service", "viewer")).body;
    expect(viewer.can.add_to_case).toBe(false);
  });
});
