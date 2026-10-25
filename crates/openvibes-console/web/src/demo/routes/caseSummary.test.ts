// The demo's case page summary answers like GET /api/v1/cases/{id}/summary
// (cases/page.rs, platform-store case_summary.rs): 404 when unseen, tiles
// that agree with the Cases list, names only with access.read, problems per
// readable kind, the can flags; and a hidden resolved item whose evidence
// came back blocks closing, whoever looks (step 5d).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CaseDetail } from "../../api/types";
import { inGroup } from "../hostGroups";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Summary = {
  code?: string;
  header: { case_id: string; status: string };
  tiles: { items: number; need_outcome: number; hosts: number; open_for_seconds: number; ready: boolean };
  details: { title: string; resolution_note: string | null };
  hosts: { agent_id: string; hostname: string | null; problems: { alarms: number | null; critical_vulns: number | null; failing_checks: number | null; compliance_stale: boolean } }[];
  people: { names: { username: string }[] | null; total: number; complete: boolean };
  can: Record<string, boolean>;
};
type Row = { case_id: string; title: string; host_count: number; takes_outcome: number; with_outcome: number; kinds: Record<string, number> };
const NOW = Date.parse("2026-10-25T12:00:00Z");
const server = (persona: Persona = "admin") => createDemoServer({ persona, now: NOW });
const call = async (s: ReturnType<typeof server>, method: string, url: string, body?: unknown, headers?: Record<string, string>) => {
  const response = await s.handle(method, url, body, headers);
  return { status: response.status, body: (await response.json().catch(() => ({}))) as Record<string, unknown> };
};
const summary = async (s: ReturnType<typeof server>, id: string) => {
  const r = await call(s, "GET", `/api/v1/cases/${id}/summary`);
  return { status: r.status, body: r.body as unknown as Summary };
};
const rows = async (s: ReturnType<typeof server>) => (await call(s, "GET", "/api/v1/case-list?status=all&limit=100")).body.items as Row[];

describe("demo case summary", () => {
  it("needs cases.read and answers 404 for a missing case", async () => {
    expect((await summary(server("operator"), "c-1")).status).toBe(403);
    const missing = await summary(server(), "00000000-0000-4000-8000-000000000000");
    expect([missing.status, missing.body.code]).toEqual([404, "case_not_found"]);
  });

  it("agrees with the Cases list row, with names and every can flag for the admin", async () => {
    const s = server();
    for (const row of await rows(s)) {
      const { status, body } = await summary(s, row.case_id);
      expect(status).toBe(200);
      expect(body.details.title).toBe(row.title);
      expect(body.tiles.items).toBe(Object.values(row.kinds).reduce((a, b) => a + b, 0));
      expect(body.tiles.need_outcome).toBe(row.takes_outcome - row.with_outcome);
      expect(body.tiles.hosts).toBe(row.host_count);
      expect(body.hosts).toHaveLength(row.host_count);
      expect(body.people.names?.length).toBe(Math.min(20, body.people.total));
      const closed = body.header.status === "closed";
      expect(body.can).toEqual({ edit: true, assign: true, close: !closed, reopen: closed, note: true, outcome: !closed, ask: false, export: true });
      if (closed) expect(body.tiles.ready).toBe(false);
    }
  });

  it("shows only the team lead's hosts, problems per readable kind and no names without access.read", async () => {
    const lee = server("team_lead");
    const pilot = lee.data.access.host_groups.find((g) => g.asset_group_id === "grp-pilot");
    const inPilot = (id: string) => {
      const a = lee.data.agents.find((x) => x.id === id);
      return !!a && !!pilot && inGroup({ ...a, last_address: lee.data.addresses.get(a.id) ?? null }, pilot);
    };
    const seen = await rows(lee);
    expect(seen.length).toBeGreaterThan(0);
    for (const row of seen) {
      const { body } = await summary(lee, row.case_id);
      expect(body.hosts.every((h) => inPilot(h.agent_id))).toBe(true);
      for (const h of body.hosts) {
        expect([h.problems.alarms, h.problems.critical_vulns].every((n) => typeof n === "number")).toBe(true);
        expect(h.problems.compliance_stale ? h.problems.failing_checks === null : typeof h.problems.failing_checks === "number").toBe(true);
      }
      // Team lead holds access.read: names shown.
      expect(body.people.names).not.toBeNull();
    }
    const sam = server("analyst");
    const first = (await rows(sam))[0] as Row;
    expect((await summary(sam, first.case_id)).body.people.names).toBeNull();
  });
});

describe("demo case people and stale hosts", () => {
  it("is complete only for a reader of every host, with or without hidden items", async () => {
    const admin = server();
    const all = await rows(admin);
    for (const row of all) expect((await summary(admin, row.case_id)).body.people.complete).toBe(true);
    const lee = server("team_lead");
    // A case of the lead's own, on a pilot host only: nothing hidden from them.
    expect((await call(lee, "POST", "/api/v1/cases", { title: "Pilot only", items: [{ kind: "host", ref: "agent-00001" }] })).status).toBe(201);
    const seen = await rows(lee);
    const total = (title: string) => all.find((r) => r.title === title)?.kinds;
    const count = (k: Record<string, number> | undefined) => Object.values(k ?? {}).reduce((a, b) => a + b, 0);
    // The seed has cases the lead sees whole and one with an item hidden from them.
    const hidden = seen.filter((r) => count(total(r.title)) > count(r.kinds));
    expect(hidden.length).toBeGreaterThan(0);
    expect(hidden.length).toBeLessThan(seen.length);
    for (const row of seen) expect((await summary(lee, row.case_id)).body.people.complete).toBe(false);
  });

  it("names only people who hold cases.read", async () => {
    const s = server();
    const readers = new Set(s.data.access.users.filter((u) => u.user_id === "u-admin" || ["u-sam", "u-vic", "u-wen", "u-lee"].includes(u.user_id)).map((u) => u.username));
    for (const row of await rows(s)) {
      for (const n of (await summary(s, row.case_id)).body.people.names ?? []) expect(readers.has(n.username), n.username).toBe(true);
    }
  });

  it("gives a host with no compliance report in a day no failing count", async () => {
    const s = server();
    const row = (await rows(s)).find((r) => r.host_count > 0) as Row;
    const first = (await summary(s, row.case_id)).body.hosts[0];
    const agent = s.data.agents.find((a) => a.id === first?.agent_id);
    if (!agent) throw new Error("no host");
    agent.last_seen_at = new Date(NOW - 2 * 86_400_000).toISOString();
    const h = (await summary(s, row.case_id)).body.hosts.find((x) => x.agent_id === agent.id);
    expect(h?.problems).toMatchObject({ failing_checks: null, compliance_stale: true });
  });
});

describe("demo case evidence, whoever looks", () => {
  const store = new Map<string, string>();
  beforeEach(() => {
    store.clear();
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v), removeItem: (k: string) => void store.delete(k),
    });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("a hidden resolved item whose evidence is back blocks ready and close", async () => {
    const admin = server();
    const pilot = admin.data.access.host_groups.find((g) => g.asset_group_id === "grp-pilot");
    const inPilot = (id: string) => {
      const a = admin.data.agents.find((x) => x.id === id);
      return !!a && !!pilot && inGroup({ ...a, last_address: admin.data.addresses.get(a.id) ?? null }, pilot);
    };
    const free = async (id: string) => ((await call(admin, "GET", `/api/v1/cases/for-item?kind=alarm&ref=${id}`)).body.items as unknown[]).length === 0;
    const open = admin.data.alarms.filter((a) => a.state === "open");
    let shown, hidden;
    for (const a of open) if (inPilot(a.agent_id) && await free(a.id)) { shown = a; break; }
    for (const a of open) if (!inPilot(a.agent_id) && await free(a.id)) { hidden = a; break; }
    if (!shown || !hidden) throw new Error("the seed needs a free open alarm in and out of the pilot group");
    const created = await call(admin, "POST", "/api/v1/cases", { title: "Evidence back", items: [{ kind: "alarm", ref: shown.id }, { kind: "alarm", ref: hidden.id }] });
    const c = created.body as unknown as CaseDetail;
    const item = (ref: string) => c.items.find((i) => i.ref === ref)?.item_id ?? "";
    // In the admin's data the hidden alarm is mitigated, so resolved is allowed.
    hidden.state = "mitigated";
    expect((await call(admin, "PUT", `/api/v1/cases/${c.case_id}/items/${item(hidden.id)}/outcome`, { outcome: "resolved" })).status).toBe(200);
    expect((await call(admin, "PUT", `/api/v1/cases/${c.case_id}/items/${item(shown.id)}/outcome`, { outcome: "false_positive", note: "n" })).status).toBe(200);
    expect((await summary(admin, c.case_id)).body.tiles.ready).toBe(true);

    // The lead's demo has the alarm open again: its evidence is back.
    const lee = server("team_lead");
    const page = await summary(lee, c.case_id);
    expect(page.body.tiles).toMatchObject({ items: 1, need_outcome: 0, ready: false });
    const current = await call(lee, "GET", `/api/v1/cases/${c.case_id}`);
    const close = await call(lee, "PUT", `/api/v1/cases/${c.case_id}`, { title: "Evidence back", severity: (current.body as { severity: string }).severity, status: "closed", assignee_user_id: null, closing_note: "done" },
      { "If-Match": `"${(current.body as { version: number }).version}"` });
    expect([close.status, close.body.code]).toEqual([409, "hidden_items_unresolved"]);
  });
});
