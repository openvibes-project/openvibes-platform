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

  it("takes exploited, due, CVSS and EPSS per CVE, not from the covering advisory", async () => {
    const row = (await get("state=all&q=CVE-2026-20051")).body.items[0];
    expect(row).toMatchObject({ key: "CVE-2026-20051", exploited: false, due: null, cvss: 5.3, epss: 0.008 });
    // Its advisory also names the exploited CVE-2026-20037, which keeps its own facts.
    expect((await get("state=all&q=CVE-2026-20037")).body.items[0]).toMatchObject({ exploited: true, cvss: 9.8 });
    for (const signal of ["exploited", "due30"]) {
      const listed = (await get(`state=all&signal=${signal}&limit=100`)).body;
      expect(listed.items.map((r) => r.key)).not.toContain("CVE-2026-20051");
      expect(listed.items.map((r) => r.key)).toContain("CVE-2026-20037");
    }
    const page = await createDemoServer({ persona: "admin" }).handle("GET", "/api/v1/vulnerabilities/CVE-2026-20051/summary", undefined);
    const summary = (await page.json()) as { header: { kev_due: string | null }; tiles: { cvss: number | null; epss_percentile: number | null } };
    expect(summary.header.kev_due).toBeNull();
    expect(summary.tiles).toMatchObject({ cvss: 5.3, epss_percentile: 0.008 * 1.6 });
  });

  it("bulk on a CVE row's advisories changes only open pairs; no-fix pairs can't be triaged", async () => {
    const server = createDemoServer({ persona: "admin" });
    const call = async (method: string, path: string, body?: unknown) => (await server.handle(method, path, body)).json();
    // A list row on the Host chip names the host but says open_only: agent-00012's mitigated pair stays.
    const hostRow = (await call("POST", "/api/v1/vulnerabilities/bulk", { action: "assign", assignee: "sam",
      items: [{ advisory_id: "FEDORA-2026-5b1e0c11", agent_id: "agent-00012", open_only: true }] })) as { changed: number; skipped: { id: string; reason: string }[] };
    expect(hostRow).toMatchObject({ changed: 0, skipped: [{ id: "agent-00012/FEDORA-2026-5b1e0c11", reason: "not open" }] });
    const named = (await call("POST", "/api/v1/vulnerabilities/bulk", { action: "assign", assignee: "sam",
      items: [{ advisory_id: "FEDORA-2026-5b1e0c11", agent_id: "agent-00012" }] })) as { changed: number };
    expect(named.changed).toBe(1);
    expect((await server.handle("POST", "/api/v1/alarms/bulk", { action: "assign", assignee: null, items: [{ id: "1", open_only: true }] })).status).toBe(400);
    const list = (await call("GET", `${URL}?state=all&limit=100`)) as VulnList;
    const shared = list.items.find((r) => r.advisories.some((a) => a.startsWith("DSA-")) && r.advisories.some((a) => a.startsWith("FEDORA-")));
    expect(shared).toBeDefined();
    const items = (shared?.advisories ?? []).map((advisory_id) => ({ advisory_id }));
    const result = (await call("POST", "/api/v1/vulnerabilities/bulk", { action: "state", state: "false_positive", note: "lab", items })) as
      { changed: number; skipped: { id: string; reason: string }[] };
    expect(result.changed).toBe(shared?.open);
    // Closed pairs reached through an advisory are not part of the action, so none is listed.
    expect(result.skipped.filter((s) => s.id.includes("/"))).toEqual([]);
    const after = (await call("GET", `${URL}?state=all&q=${shared?.key ?? ""}`)) as VulnList;
    expect(after.items[0]?.open).toBe(0);
    // Assign skips the closed ones too.
    const assign = (await call("POST", "/api/v1/vulnerabilities/bulk", { action: "assign", assignee: "sam", items })) as { changed: number; skipped: { reason: string }[] };
    expect(assign.changed).toBe(0);
    expect(assign.skipped).toEqual(items.map((i) => ({ id: i.advisory_id, reason: "not open" })));
    const nofix = list.items.find((r) => r.fixed.kind === "none" && r.open > 0);
    const skipped = (await call("POST", "/api/v1/vulnerabilities/bulk", { action: "assign", assignee: "sam",
      items: (nofix?.advisories ?? []).map((advisory_id) => ({ advisory_id })) })) as { changed: number; skipped: { reason: string }[] };
    expect(skipped.changed).toBe(0);
    expect(skipped.skipped.map((s) => s.reason)).toContain("not found or out of scope");
  });
});
