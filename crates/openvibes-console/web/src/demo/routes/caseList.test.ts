// The demo's Cases list answers like GET /api/v1/case-list (cases/list_page.rs,
// platform-store case_list.rs): validation naming the parameter, the active
// default, rows over visible items, counts with the other filters applied,
// the summary, reach, and the seed's cases (step 5d).
import { describe, expect, it } from "vitest";

import type { CaseDetail } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Row = {
  case_id: string; number: number; title: string; status: string; severity: string; assignee: { user_id: string } | null;
  latest_note: { text: string } | null; hosts: { agent_id: string }[]; host_count: number; with_outcome: number; takes_outcome: number;
  kinds: Record<string, number>; ready: boolean; updated_at: string;
};
type Count = { value: string; count: number };
type Body = {
  items: Row[]; total: number; field_errors?: { field: string }[];
  counts: { status: Count[]; severity: Count[]; contains: Count[]; updated: Count[]; group: Count[]; assignee: { me: number; unassigned: number; people: Count[] } };
  summary: { open: number; investigating: number; unassigned: number; ready_to_close: number };
};
const URL = "/api/v1/case-list";
const ask = async (server: ReturnType<typeof createDemoServer>, query = "") => {
  const response = await server.handle("GET", `${URL}${query ? `?${query}` : ""}`, undefined);
  return { status: response.status, body: (await response.json()) as Body };
};
const get = (query = "", persona: Persona = "admin") => ask(createDemoServer({ persona }), query);
const n = (counts: Count[], value: string) => counts.find((c) => c.value === value)?.count;
const titled = (b: Body, pattern: RegExp) => b.items.find((r) => pattern.test(r.title));

describe("demo Cases list", () => {
  it.each([
    ["status=gone", "status"], ["severity=info", "severity"], ["assignee=Nobody", "assignee"], ["contains=hosts", "contains"],
    ["host=%00", "host"], ["group=!", "group"], ["updated=month", "updated"], ["sort=title", "sort"], ["dir=up", "dir"],
    ["offset=-1", "offset"], ["offset=100001", "offset"], [`q=${"x".repeat(201)}`, "q"], ["cursor=abc", "query"],
  ])("refuses %s naming %s", async (query, field) => {
    const { status, body } = await get(query);
    expect(status).toBe(400);
    expect(body.field_errors?.[0]?.field).toBe(field);
  });

  it("needs cases.read", async () => {
    expect((await get("", "operator")).status).toBe(403);
  });

  it("lists cases that are not closed, newest change first, with counts and the summary", async () => {
    const { status, body } = await get("limit=100");
    expect(status).toBe(200);
    expect(body.items.every((r) => r.status !== "closed")).toBe(true);
    expect(body.items.map((r) => r.updated_at)).toEqual([...body.items.map((r) => r.updated_at)].sort().reverse());
    expect(body.total).toBe(body.items.length);
    expect(n(body.counts.status, "active")).toBe(body.total);
    expect(n(body.counts.status, "all")).toBe(body.total + (n(body.counts.status, "closed") ?? 0));
    expect(body.summary.open + body.summary.investigating).toBe(body.total);
    const ssh = titled(body, /SSH open/);
    expect(ssh).toMatchObject({ takes_outcome: 2, with_outcome: 0, host_count: 1, kinds: { alarms: 1, findings: 1, hosts: 1 }, ready: false });
    expect(ssh?.latest_note?.text.length).toBeLessThanOrEqual(120);
    const all = (await get("status=all&limit=100")).body;
    expect(all.items.filter((r) => r.status === "closed").length).toBeGreaterThanOrEqual(2);
  });

  it("seeds an empty case, a software-only case and a quiet one, which are ready, hostless and quiet", async () => {
    const { body } = await get("limit=100");
    const empty = titled(body, /Windows baseline/);
    expect(empty).toMatchObject({ takes_outcome: 0, host_count: 0, hosts: [], ready: true });
    const software = titled(body, /old openssl/);
    expect(software).toMatchObject({ host_count: 0, kinds: { software: 1 } });
    const quiet = (await get("updated=quiet&limit=100")).body;
    expect(quiet.items.map((r) => r.title)).toEqual([expect.stringMatching(/cron/)]);
    expect(n(body.counts.updated, "quiet")).toBe(1);
    expect(body.summary.ready_to_close).toBeGreaterThanOrEqual(2);
  });

  it("clears the seed's run-out acceptance when the cases are first read", async () => {
    const { body } = await get("limit=100");
    expect(titled(body, /Noisy backup/)).toMatchObject({ takes_outcome: 1, with_outcome: 0 });
  });

  it("seeds every outcome, and a closed case with no resolution", async () => {
    const server = createDemoServer({ persona: "admin" });
    const all = (await ask(server, "status=all&limit=100")).body;
    const outcomes = new Set<string>();
    for (const r of all.items) {
      const detail = (await (await server.handle("GET", `/api/v1/cases/${r.case_id}`, undefined)).json()) as CaseDetail;
      for (const i of detail.items) if (i.outcome) outcomes.add(i.outcome);
      if (/Miner/.test(r.title)) expect(detail).toMatchObject({ status: "closed", resolution: null, resolution_note: expect.any(String) });
    }
    expect([...outcomes].sort()).toEqual(["accepted_risk", "confirmed_malicious", "expected", "false_positive", "resolved"]);
  });

  it("shows the pilot lead only cases on the hosts they see, a hidden item keeping its case from being ready", async () => {
    const lead = (await get("status=all&limit=100", "team_lead")).body;
    const admin = (await get("status=all&limit=100")).body;
    expect(lead.total).toBeLessThan(admin.total);
    expect(titled(lead, /Windows baseline/)).toBeUndefined();
    const mixed = titled(lead, /pilot and one more/);
    expect(mixed).toMatchObject({ takes_outcome: 1, with_outcome: 1, host_count: 1, ready: false });
    expect(titled(admin, /pilot and one more/)).toMatchObject({ takes_outcome: 2, host_count: 2 });
    const mine = (await get("assignee=me&limit=100", "team_lead")).body;
    expect(mine.items.map((r) => r.title)).toEqual([expect.stringMatching(/pilot and one more/)]);
    expect(mine.counts.assignee.me).toBe(1);
    expect(mine.summary.ready_to_close).toBe(0);
  });

  it("filters, searches, sorts and pages", async () => {
    const all = (await get("status=all&limit=100&sort=number&dir=asc")).body;
    expect(all.items.map((r) => r.number)).toEqual([...all.items.map((r) => r.number)].sort((a, b) => a - b));
    const first = all.items[0] as Row;
    expect((await get(`q=C-${first.number}&status=all`)).body.items.map((r) => r.number)).toEqual([first.number]);
    expect((await get("status=all&limit=1&offset=1&sort=number&dir=asc")).body.items[0]?.number).toBe(all.items[1]?.number);
    const vulns = (await get("contains=vulnerabilities&limit=100")).body;
    expect(vulns.items.length).toBeGreaterThan(0);
    expect(vulns.items.every((r) => (r.kinds.vulnerabilities ?? 0) > 0)).toBe(true);
    const host = titled(all, /SSH open/)?.hosts[0]?.agent_id ?? "";
    expect((await get(`host=${host}&status=all`)).body.items.every((r) => r.hosts.some((h) => h.agent_id === host))).toBe(true);
    const critical = (await get("severity=critical&limit=100")).body;
    expect(critical.items.every((r) => r.severity === "critical")).toBe(true);
    expect(n((await get("limit=100")).body.counts.severity, "critical")).toBe(critical.total);
  });
});
