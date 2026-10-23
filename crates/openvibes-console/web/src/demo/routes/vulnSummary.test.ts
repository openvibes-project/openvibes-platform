// The demo's vulnerability page answers like GET /api/v1/vulnerabilities/{key}/summary
// and /{key}/hosts (vulnerabilities/page.rs): key resolution, the cards, the
// Hosts table's segments and paging, validation and reach.
import { describe, expect, it } from "vitest";

import type { VulnHostsPage, VulnList, VulnSummaryPage } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Problem = { code?: string; field_errors?: { field: string; message: string }[] };
const get = async <T,>(url: string, persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", url, undefined);
  return { status: response.status, body: (await response.json()) as T & Problem };
};
const summary = (key: string, persona?: Persona) => get<VulnSummaryPage>(`/api/v1/vulnerabilities/${encodeURIComponent(key)}/summary`, persona);
const hosts = (key: string, query = "", persona?: Persona) => get<VulnHostsPage>(`/api/v1/vulnerabilities/${encodeURIComponent(key)}/hosts?${query}`, persona);
const firstRow = async (persona: Persona = "admin") =>
  (await get<VulnList>("/api/v1/vulnerability-list?state=all&limit=100", persona)).body.items;

describe("demo vulnerability page", () => {
  it("agrees with the list row and adds what to do, details and actions", async () => {
    const rows = await firstRow();
    const row = rows[0];
    if (!row) throw new Error("no rows");
    const { status, body } = await summary(row.key);
    expect(status).toBe(200);
    expect(body.key).toBe(row.key);
    expect([body.header.open, body.header.total]).toEqual([row.open, row.total]);
    expect(body.header.packages).toEqual(row.packages);
    expect(body.details.advisories.map((a) => a.id)).toEqual(row.advisories);
    expect(body.what_to_do.length).toBeGreaterThan(0);
    expect(body.can.triage).toBe(true);
    expect(body.history).toEqual([]);
  });

  it("resolves an advisory with one CVE to it and answers 409 for several", async () => {
    const server = createDemoServer();
    const one = server.data.advisories.find((a) => a.cves.length === 1);
    const several = server.data.advisories.find((a) => a.cves.length > 1 && server.data.vulnerabilities.some((v) => v.advisory_id === a.id));
    if (!one || !several) throw new Error("fixture");
    const hit = server.data.vulnerabilities.some((v) => v.advisory_id === one.id);
    const r1 = await summary(one.id);
    expect(r1.status).toBe(hit ? 200 : 404);
    if (hit) expect(r1.body.key).toBe(one.cves[0]?.cve_id);
    const r2 = await summary(several.id);
    expect(r2.status).toBe(409);
    expect(r2.body.code).toBe("advisory_has_several_cves");
    expect(r2.body.field_errors?.map((e) => e.message)).toEqual(several.cves.map((c) => c.cve_id).sort());
    for (const key of ["CVE-NOPE", "CPE:CVE-1:x", "C".repeat(257)]) expect((await summary(key)).status).toBe(404);
  });

  it("pages the Hosts table with segments that add up", async () => {
    const row = (await firstRow())[0];
    if (!row) throw new Error("no rows");
    const { status, body } = await hosts(row.key);
    expect(status).toBe(200);
    const s = body.segments;
    expect(s.open + s.mitigated + s.resolved).toBe(s.all);
    expect(body.total).toBe(s.all);
    expect((await hosts(row.key, "segment=open")).body.total).toBe(s.open);
    expect((await hosts(row.key, "offset=1&limit=1")).body.rows[0]).toEqual(body.rows[1]);
    for (const [query, field] of [["segment=fixed", "segment"], ["offset=-1", "offset"], ["sort=x", "query"]]) {
      const r = await hosts(row.key, query);
      expect(r.status).toBe(400);
      expect(r.body.field_errors?.[0]?.field).toBe(field);
    }
  });

  it("keeps a scoped persona inside its reach", async () => {
    const all = new Set((await firstRow()).map((r) => r.key));
    const scoped = new Set((await firstRow("scoped_operator")).map((r) => r.key));
    const outside = [...all].find((k) => !scoped.has(k));
    if (outside) expect((await summary(outside, "scoped_operator")).status).toBe(404);
    const inside = [...scoped][0];
    if (inside) {
      const { body } = await summary(inside, "scoped_operator");
      expect(body.header.total).toBe((await firstRow("scoped_operator")).find((r) => r.key === inside)?.total);
    }
  });

  it("marks a CVE exploited from EUVD alone (no due date) and names the advisory its title is from", async () => {
    const server = createDemoServer();
    const cve = server.data.advisories.flatMap((a) => a.cves).find((c) => c.cve_id === "CVE-2026-10000");
    if (!cve) throw new Error("fixture");
    const read = async () => (await (await server.handle("GET", "/api/v1/vulnerabilities/CVE-2026-10000/summary", undefined)).json()) as VulnSummaryPage;
    expect((await read()).header.exploited).toBe(cve.kev || cve.euvd_exploited != null);
    Object.assign(cve, { kev: false, euvd_exploited: new Date().toISOString() });
    const body = await read();
    expect(body.header.exploited).toBe(true);
    expect(body.header.kev_due).toBeNull();
    expect(body.header.advisory_id).toBe("FEDORA-2026-3a1f9c0d");
    // The list agrees.
    const list = (await (await server.handle("GET", "/api/v1/vulnerability-list?state=all&q=CVE-2026-10000", undefined)).json()) as VulnList;
    expect(list.items.find((r) => r.key === "CVE-2026-10000")?.exploited).toBe(true);
  });
});
