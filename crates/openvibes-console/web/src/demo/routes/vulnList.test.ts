// The demo's Vulnerabilities list answers like GET /api/v1/vulnerability-list
// (vulnerabilities/list_page.rs): validation, one row per CVE, the open
// default, counts with the other filters applied, the summary and reach.
import { describe, expect, it } from "vitest";

import type { VulnList } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Body = VulnList & { field_errors?: { field: string }[] };
const URL = "/api/v1/vulnerability-list";
const get = async (query = "", persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", `${URL}${query ? `?${query}` : ""}`, undefined);
  return { status: response.status, body: (await response.json()) as Body };
};
const keys = (b: VulnList) => b.items.map((i) => i.key);
const n = (counts: { value: string; count: number }[], value: string) => counts.find((c) => c.value === value)?.count;

describe("demo Vulnerabilities list", () => {
  it.each([
    ["state=gone", "state"], ["severity=high", "severity"], ["signal=loud", "signal"], ["package=%00", "package"], ["group=!", "group"],
    ["host=%00", "host"], ["advisory=%00", "advisory"], ["assignee=Nobody", "assignee"], ["sort=colour", "sort"], ["dir=up", "dir"],
    ["offset=-1", "offset"], ["offset=100001", "offset"], [`q=${"x".repeat(201)}`, "q"],
  ])("refuses %s naming %s", async (query, field) => {
    const { status, body } = await get(query);
    expect(status).toBe(400);
    expect(body.field_errors?.[0]?.field).toBe(field);
  });

  it("refuses a limit outside 1 to 100", async () => {
    for (const limit of ["0", "101"]) expect((await get(`limit=${limit}`)).status).toBe(400);
  });

  it("has one row per CVE with its pairs, and counts that agree with the filters", async () => {
    const { status, body } = await get("state=all&limit=100");
    expect(status).toBe(200);
    expect(new Set(keys(body)).size).toBe(body.items.length);
    expect(body.total).toBeGreaterThan(5);
    for (const r of body.items) {
      expect(r.total).toBeGreaterThanOrEqual(r.open);
      expect(r.advisories.length).toBeGreaterThan(0);
    }
    expect(n(body.counts.state, "all")).toBe(body.total);
    const critical = (await get("state=all&severity=critical&limit=100")).body;
    expect(critical.items.every((r) => r.severity === "critical")).toBe(true);
    expect(critical.total).toBe(n(body.counts.severity, "critical"));
    const exploited = (await get("state=all&signal=exploited&limit=100")).body;
    expect(exploited.items.every((r) => r.exploited)).toBe(true);
    expect(exploited.total).toBe(n(body.counts.signal, "exploited"));
  });

  it("defaults to open rows and keeps the summary under state", async () => {
    const open = (await get()).body;
    expect(open.items.every((r) => r.open > 0)).toBe(true);
    expect(open.summary.open_rows).toBe(open.total);
    const resolved = (await get("state=resolved")).body;
    expect(resolved.total).toBeGreaterThan(0);
    expect(resolved.summary).toEqual(open.summary);
  });

  it("sorts, pages and breaks ties by key", async () => {
    const full = (await get("state=all&sort=cvss&dir=desc&limit=100")).body;
    const cvss = full.items.map((r) => r.cvss ?? -1);
    expect(cvss).toEqual([...cvss].sort((a, b) => b - a));
    const second = (await get("state=all&sort=cvss&dir=desc&limit=1&offset=1")).body;
    expect(keys(second)).toEqual([full.items[1]?.key]);
    expect(second.total).toBe(full.total);
  });

  it("keeps a team lead to their groups", async () => {
    const admin = (await get("state=all&limit=100")).body;
    const lead = await get("state=all&limit=100", "team_lead");
    expect(lead.status).toBe(200);
    expect(lead.body.total).toBeGreaterThan(0);
    expect(lead.body.total).toBeLessThan(admin.total);
  });

  it("shows lower-confidence matches only under that signal, and counts them", async () => {
    const all = (await get("state=all&limit=100")).body;
    expect(all.items.some((r) => r.low_confidence || r.advisories.some((a) => a.startsWith("CPE:")))).toBe(false);
    const low = (await get("state=all&signal=lowconf&limit=100")).body;
    expect(low.total).toBeGreaterThan(0);
    expect(low.items.every((r) => r.low_confidence)).toBe(true);
    expect(n(all.counts.signal, "lowconf")).toBe(low.total);
    expect(n(low.counts.signal, "exploited")).toBe(n(all.counts.signal, "exploited"));
  });

  it("has the cases the list must show: a CVE across distributions, fixed pairs, due dates and assignees", async () => {
    const all = (await get("state=all&limit=100")).body;
    const rows = [...all.items, ...(await get("state=all&limit=100&offset=100")).body.items];
    const shared = rows.find((r) => r.advisories.some((a) => a.startsWith("FEDORA-")) && r.advisories.some((a) => a.startsWith("DSA-")));
    expect(shared?.fixed.kind).toBe("several");
    expect(shared?.also_covers.length).toBeGreaterThan(0);
    expect(n(all.counts.state, "resolved")).toBeGreaterThan(0);
    expect(n(all.counts.state, "mitigated")).toBeGreaterThan(0);
    expect(rows.some((r) => r.fixed.kind === "none")).toBe(true);
    const today = new Date().toISOString().slice(0, 10);
    const in30 = new Date(Date.now() + 30 * 86_400_000).toISOString().slice(0, 10);
    expect(rows.some((r) => r.due != null && r.due < today)).toBe(true);
    expect(rows.some((r) => r.due != null && r.due >= today && r.due <= in30)).toBe(true);
    expect(rows.some((r) => r.due != null && r.due > in30)).toBe(true);
    for (const kind of ["none", "one", "several"]) expect(rows.some((r) => r.assignee.kind === kind)).toBe(true);
  });

  it("bulk on a CVE row's advisories changes only open pairs; no-fix pairs can't be triaged", async () => {
    const server = createDemoServer({ persona: "admin" });
    const call = async (method: string, path: string, body?: unknown) => (await server.handle(method, path, body)).json();
    const list = (await call("GET", `${URL}?state=all&limit=100`)) as VulnList;
    const shared = list.items.find((r) => r.advisories.some((a) => a.startsWith("DSA-")) && r.advisories.some((a) => a.startsWith("FEDORA-")));
    expect(shared).toBeDefined();
    const items = (shared?.advisories ?? []).map((advisory_id) => ({ advisory_id }));
    const result = (await call("POST", "/api/v1/vulnerabilities/bulk", { action: "state", state: "false_positive", note: "lab", items })) as
      { changed: number; skipped: { id: string; reason: string }[] };
    expect(result.changed).toBe(shared?.open);
    expect(result.skipped.some((s) => s.reason === "not open")).toBe(true);
    const after = (await call("GET", `${URL}?state=all&q=${shared?.key ?? ""}`)) as VulnList;
    expect(after.items[0]?.open).toBe(0);
    // Assign skips the closed ones too.
    const assign = (await call("POST", "/api/v1/vulnerabilities/bulk", { action: "assign", assignee: "sam", items })) as { changed: number; skipped: { reason: string }[] };
    expect(assign.changed).toBe(0);
    expect(assign.skipped.every((s) => s.reason === "not open")).toBe(true);
    const nofix = list.items.find((r) => r.fixed.kind === "none" && r.open > 0);
    const skipped = (await call("POST", "/api/v1/vulnerabilities/bulk", { action: "assign", assignee: "sam",
      items: (nofix?.advisories ?? []).map((advisory_id) => ({ advisory_id })) })) as { changed: number; skipped: { reason: string }[] };
    expect(skipped.changed).toBe(0);
    expect(skipped.skipped.map((s) => s.reason)).toContain("not found or out of scope");
  });
});
