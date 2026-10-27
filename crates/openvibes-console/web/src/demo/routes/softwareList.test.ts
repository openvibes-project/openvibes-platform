// The demo's Software list answers like GET /api/v1/software-list
// (software_pages/list_page.rs, platform-store software_list.rs): validation,
// one row per package name, counts with the other filters applied, the
// summary, the fix and used-by columns and reach.
import { describe, expect, it } from "vitest";

import type { SoftwareList } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Body = SoftwareList & { field_errors?: { field: string }[] };
const URL = "/api/v1/software-list";
const get = async (query = "", persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", `${URL}${query ? `?${query}` : ""}`, undefined);
  return { status: response.status, body: (await response.json()) as Body };
};
const names = (b: SoftwareList) => b.items.map((i) => i.name);
const n = (counts: { value: string; count: number }[], value: string) => counts.find((c) => c.value === value)?.count;

describe("demo Software list", () => {
  it.each([
    ["vulns=bad", "vulns"], ["fix=maybe", "fix"], ["versions=two", "versions"], ["type=deb", "type"], ["changes=old", "changes"], ["group=!", "group"], ["host=%00", "host"],
    ["sort=colour", "sort"], ["dir=up", "dir"], ["offset=-1", "offset"], [`q=${"x".repeat(201)}`, "q"], ["fixable=true", "query"],
  ])("refuses %s naming %s", async (query, field) => {
    const { status, body } = await get(query);
    expect(status).toBe(400);
    expect(body.field_errors?.[0]?.field).toBe(field);
  });

  it("lists one row per package name, with the hosts that have it", async () => {
    const { body } = await get("limit=100");
    const all = names(body);
    expect(new Set(all).size).toBe(all.length);
    expect(all).toEqual([...all].sort());
    expect(body.total).toBe(all.length);
    const openssl = body.items.find((i) => i.name === "openssl");
    expect(openssl?.hosts).toBeGreaterThan(1);
    expect(openssl?.advisories).toBeGreaterThan(0);
  });

  it("counts each filter value with the other filters applied", async () => {
    const all = (await get("limit=100")).body;
    expect((n(all.counts.vulns, "any") ?? 0) + (n(all.counts.vulns, "none") ?? 0)).toBe(all.total);
    const several = (await get("versions=several&limit=100")).body;
    expect(several.total).toBe(n(all.counts.versions, "several"));
    expect(several.items.every((i) => i.versions > 1)).toBe(true);
    expect(several.summary.several_versions).toBe(several.total);
  });

  it("separates what has an update from what has no fix yet", async () => {
    const fix = (await get("fix=available&limit=100")).body;
    expect(fix.items.every((i) => i.update_hosts > 0)).toBe(true);
    const none = (await get("fix=none&limit=100")).body;
    expect(none.items.every((i) => i.no_fix > 0)).toBe(true);
    expect(fix.summary.fixable).toBe(fix.total);
  });

  it("searches by package and by the service that runs from it", async () => {
    expect(names((await get("q=openssl")).body)).toContain("openssl");
    expect((await get("q=zzzz")).body.total).toBe(0);
  });

  it("sorts and pages", async () => {
    const byHosts = (await get("sort=hosts&dir=desc&limit=100")).body;
    expect(byHosts.items.map((i) => i.hosts)).toEqual([...byHosts.items.map((i) => i.hosts)].sort((a, b) => b - a));
    const second = (await get("limit=2&offset=2")).body;
    expect(second.items).toHaveLength(2);
    expect(names(second)).toEqual(names((await get("limit=100")).body).slice(2, 4));
  });

  it("answers within the scoped operator's reach", async () => {
    const full = (await get("")).body;
    const scoped = (await get("", "scoped_operator")).body;
    expect(scoped.total).toBeLessThanOrEqual(full.total);
    expect(scoped.summary.reporting_hosts).toBeLessThan(full.summary.reporting_hosts);
  });
});
