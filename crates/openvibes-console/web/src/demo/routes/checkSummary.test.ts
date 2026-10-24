// The demo's check page answers like GET /api/v1/compliance/checks/{set}/{rule}/summary
// and /hosts (compliance/page.rs): it agrees with the Compliance list row, the
// Hosts segments add up and page, masked evidence has no value, and a check
// out of reach is 404.
import { describe, expect, it } from "vitest";

import type { CheckHostsPage, CheckList, CheckSummaryPage } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Problem = { code?: string; field_errors?: { field: string }[] };
const get = async <T,>(url: string, persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", url, undefined);
  return { status: response.status, body: (await response.json()) as T & Problem };
};
const url = (set: string, rule: string, tail: string) => `/api/v1/compliance/checks/${encodeURIComponent(set)}/${encodeURIComponent(rule)}/${tail}`;
const summary = (set: string, rule: string, persona?: Persona) => get<CheckSummaryPage>(url(set, rule, "summary"), persona);
const hosts = (set: string, rule: string, query = "", persona?: Persona) => get<CheckHostsPage>(`${url(set, rule, "hosts")}?${query}`, persona);
const list = async (persona: Persona = "admin") => (await get<CheckList>("/api/v1/compliance-list?state=all&limit=100", persona)).body.items;

describe("demo check page", () => {
  it("agrees with every list row", async () => {
    for (const persona of ["admin", "scoped_operator"] as Persona[]) {
      const rows = await list(persona);
      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) {
        const { status, body } = await summary(row.rule_set_id, row.rule_id, persona);
        expect(status).toBe(200);
        expect([body.tiles.failing, body.tiles.passing, body.header.title, body.header.severity ?? undefined])
          .toEqual([row.failing, row.passing, row.title, row.severity]);
        expect(body.header.assignee).toEqual(row.assignee);
        expect(body.tiles.days).toHaveLength(14);
        expect(body.tiles.days[13]).toBe(row.failing);
      }
    }
  });

  it("has the cards and the actions", async () => {
    const { body } = await summary("baseline", "port.ssh.exposed");
    expect(body.header.area).toBe("Network exposure");
    expect(body.related.port).toMatchObject({ protocol: "tcp", port: 22 });
    expect(body.details.applies_to).toBe("All hosts");
    expect(body.history.some((e) => e.kind === "published")).toBe(true);
    expect(body.can.triage).toBe(true);
    // Triage needs a failing host: a check only passing offers none.
    const passingOnly = (await list()).find((r) => r.failing === 0);
    if (!passingOnly) throw new Error("fixture");
    const p = (await summary(passingOnly.rule_set_id, passingOnly.rule_id)).body;
    expect([p.can.triage, p.can.assign]).toEqual([false, false]);
    const avahi = (await summary("hardening-linux-l1", "harden.services.avahi")).body;
    expect(avahi.details.applies_to).toBe("Linux hosts");
  });

  it("pages the Hosts table with segments that add up", async () => {
    const { status, body } = await hosts("baseline", "port.ssh.exposed");
    expect(status).toBe(200);
    const s = body.segments;
    expect(s.failing + s.passing).toBe(s.all);
    expect(body.total).toBe(s.all);
    expect((await hosts("baseline", "port.ssh.exposed", "segment=passing")).body.rows.every((r) => r.state === "passing")).toBe(true);
    const page = await hosts("baseline", "port.ssh.exposed", "segment=failing&limit=2&offset=1");
    expect(page.body.rows.length).toBeLessThanOrEqual(2);
    expect(page.body.total).toBe(s.failing);
    for (const r of body.rows) {
      for (const e of r.evidence) if (e.status) expect(e.value).toBeUndefined();
      if (r.state === "passing") expect([r.evidence, r.triage_version]).toEqual([[], null]);
    }
    for (const [q, field] of [["segment=open", "segment"], ["offset=-1", "offset"], ["x=1", "query"]]) {
      const r = await hosts("baseline", "port.ssh.exposed", q);
      expect([r.status, r.body.field_errors?.[0]?.field]).toEqual([400, field]);
    }
  });

  it("answers 404 for a check it does not have or out of reach", async () => {
    for (const [set, rule] of [["baseline", "no.such"], ["nope", "x"]]) {
      const r = await summary(set ?? "", rule ?? "");
      expect([r.status, r.body.code]).toEqual([404, "check_not_found"]);
      expect((await hosts(set ?? "", rule ?? "")).status).toBe(404);
    }
    const all = new Set((await list()).map((r) => `${r.rule_set_id}/${r.rule_id}`));
    const scoped = new Set((await list("scoped_operator")).map((r) => `${r.rule_set_id}/${r.rule_id}`));
    for (const key of all) {
      if (scoped.has(key)) continue;
      const [set = "", rule = ""] = [key.slice(0, key.indexOf("/")), key.slice(key.indexOf("/") + 1)];
      expect((await summary(set, rule, "scoped_operator")).status).toBe(404);
    }
  });
});
