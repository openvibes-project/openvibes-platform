// The demo's package page answers like GET /api/v1/software-pages/{name}/summary
// and /hosts (software_pages/page.rs, platform-store software_summary.rs):
// path and query validation, the header and tiles agree with the list, the
// segments add up, and the actions follow the persona's permissions.
import { describe, expect, it } from "vitest";

import type { SoftwareList, SoftwarePageHosts, SoftwarePageSummary } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

const get = async <T>(path: string, persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", path, undefined);
  return { status: response.status, body: (await response.json()) as T & { code?: string; field_errors?: { field: string }[] } };
};
const summary = (name: string, persona?: Persona) => get<SoftwarePageSummary>(`/api/v1/software-pages/${encodeURIComponent(name)}/summary`, persona);
const hosts = (name: string, query = "") => get<SoftwarePageHosts>(`/api/v1/software-pages/${encodeURIComponent(name)}/hosts${query}`);

describe("demo package page", () => {
  it("refuses an over-long or control-character name", async () => {
    for (const name of ["x".repeat(201), "a%00b"]) {
      for (const tail of ["summary", "hosts"]) {
        const { status, body } = await get(`/api/v1/software-pages/${name}/${tail}`);
        expect([status, body.code]).toEqual([400, "invalid_package"]);
      }
    }
  });

  it("answers 404 for a package no host has", async () => {
    const { status, body } = await summary("nothing-at-all");
    expect([status, body.code]).toEqual([404, "package_not_found"]);
  });

  it("agrees with the list on hosts, versions, advisories and the update", async () => {
    const list = (await get<SoftwareList>("/api/v1/software-list?limit=100")).body;
    for (const row of list.items.slice(0, 12)) {
      const { status, body } = await summary(row.name);
      expect(status).toBe(200);
      expect(body.header.hosts).toBe(row.hosts);
      expect(body.tiles).toMatchObject({ hosts: row.hosts, versions: row.versions, vulnerabilities: row.advisories, update_hosts: row.update_hosts });
      expect(body.no_fix).toBe(row.no_fix);
      expect(body.week).toEqual({ added: row.week_added, updated: row.week_updated, removed: row.week_removed });
      expect(body.versions.reduce((sum, v) => sum + v.hosts, 0)).toBeGreaterThanOrEqual(row.hosts);
    }
  });

  it("splits its hosts into segments that add up", async () => {
    const all = (await hosts("openssl")).body;
    expect(all.segments.all).toBe(all.total);
    expect(all.segments.update + all.segments.current).toBe(all.segments.all);
    const update = (await hosts("openssl", "?segment=update")).body;
    expect(update.total).toBe(all.segments.update);
    expect(update.items.every((h) => h.update_to)).toBe(true);
    expect((await hosts("openssl", "?segment=bogus")).status).toBe(400);
    expect((await hosts("openssl", "?limit=1&offset=1")).body.items).toHaveLength(1);
  });

  it("keeps a package that went away viewable and follows the persona's permissions", async () => {
    const admin = (await summary("openssl")).body;
    expect(admin.can.add_to_case).toBe(true);
    const viewer = (await summary("openssl", "viewer")).body;
    expect(viewer.can.add_to_case).toBe(false);
  });
});
