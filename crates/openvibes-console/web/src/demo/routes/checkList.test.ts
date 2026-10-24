// The demo's Compliance list answers like GET /api/v1/compliance-list
// (compliance/list_page.rs, platform-store check_list.rs): validation, one row
// per check, the open default, passing hosts, counts with the other filters
// applied, the summary and reach.
import { describe, expect, it } from "vitest";

import type { CheckList } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Body = CheckList & { field_errors?: { field: string }[] };
const URL = "/api/v1/compliance-list";
const get = async (query = "", persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", `${URL}${query ? `?${query}` : ""}`, undefined);
  return { status: response.status, body: (await response.json()) as Body };
};
const ids = (b: CheckList) => b.items.map((i) => i.rule_id);
const n = (counts: { value: string; count: number }[], value: string) => counts.find((c) => c.value === value)?.count;
const row = (b: CheckList, id: string) => b.items.find((i) => i.rule_id === id);

describe("demo Compliance list", () => {
  it.each([
    ["state=gone", "state"], ["state=resolved", "state"], ["severity=important", "severity"], ["rule_set=%00", "rule_set"],
    ["area=%00", "area"], ["group=!", "group"], ["host=%00", "host"], ["assignee=Nobody", "assignee"], ["sort=colour", "sort"],
    ["dir=up", "dir"], ["offset=-1", "offset"], ["offset=100001", "offset"],
    [`q=${"x".repeat(201)}`, "q"], ["window=7d", "query"],
  ])("refuses %s naming %s", async (query, field) => {
    const { status, body } = await get(query);
    expect(status).toBe(400);
    expect(body.field_errors?.[0]?.field).toBe(field);
  });

  it("refuses a limit outside 1 to 100", async () => {
    for (const limit of ["0", "101"]) expect((await get(`limit=${limit}`)).status).toBe(400);
  });

  it("defaults to rows with an open failing host and keeps the summary under state", async () => {
    const open = (await get("limit=100")).body;
    expect(open.items.every((r) => r.open > 0)).toBe(true);
    expect(open.summary.failing_checks).toBe(open.total);
    const mitigated = (await get("state=mitigated&limit=100")).body;
    expect(mitigated.items.every((r) => r.mitigated > 0)).toBe(true);
    expect(mitigated.summary).toEqual(open.summary);
    const all = (await get("state=all&limit=100")).body;
    expect(n(all.counts.state, "all")).toBe(all.total);
    expect(n(all.counts.state, "open")).toBe(open.total);
  });

  it("covers several rule sets, every area, every triage state and every assignee kind", async () => {
    const all = (await get("state=all&limit=100")).body;
    expect(new Set(all.items.map((r) => r.rule_set_id))).toEqual(new Set(["baseline", "hardening-linux-l1", "site"]));
    const areas = ["Network exposure", "Packages", "SSH", "Network", "Kernel", "Files", "Accounts", "Security modules", "Services", "Tests", "Other"];
    expect(all.counts.area.map((a) => a.value).sort()).toEqual([...areas].sort());
    for (const a of areas) expect(n(all.counts.area, a)).toBeGreaterThan(0);
    for (const s of ["open", "mitigated", "accepted_risk", "false_positive", "passing"]) expect(n(all.counts.state, s)).toBeGreaterThan(0);
    for (const kind of ["none", "one", "several"]) expect(all.items.some((r) => r.assignee.kind === kind)).toBe(true);
    for (const s of ["critical", "high", "medium", "low"]) expect(n(all.counts.severity, s)).toBeGreaterThan(0);
  });

  it("has a check only passing, a finding that ended, and an acceptance that expired", async () => {
    const all = (await get("state=all&limit=100")).body;
    expect(row(all, "harden.files.passwd")).toMatchObject({ failing: 0, since: null, assignee: { kind: "none" } });
    expect(row(all, "harden.files.passwd")?.passing).toBeGreaterThan(0);
    expect(ids((await get("state=passing&q=files.passwd")).body)).toEqual(["harden.files.passwd"]);
    expect(ids((await get("q=files.passwd")).body)).toEqual([]);
    // aslr: host 1's finding ended, host 2's still fails; the ended one counts for nothing.
    expect(row(all, "harden.kernel.aslr")).toMatchObject({ failing: 1, open: 1 });
    // permit_empty_passwords: one open, one accepted until a past date, which counts as open (Ola's).
    expect(row(all, "harden.ssh.permit_empty_passwords")).toMatchObject({ failing: 2, open: 2, accepted_risk: 0, assignee: { kind: "one", id: "u-ola" } });
    expect(row(all, "harden.ssh.permit_root_login")).toMatchObject({ failing: 5, open: 2, mitigated: 1, accepted_risk: 1, false_positive: 1 });
  });

  it("takes the severity of the newest finding, else the indexed one", async () => {
    const all = (await get("state=all&limit=100")).body;
    expect(row(all, "harden.files.passwd")?.severity).toBe("medium");
    expect(row(all, "port.docker_api.exposed")?.severity).toBe("critical");
    expect(all.items.every((r) => r.severity !== undefined)).toBe(true);
  });

  it("counts every filter's values with the others applied", async () => {
    const all = (await get("state=all&limit=100")).body;
    const critical = (await get("state=all&severity=critical&limit=100")).body;
    expect(critical.items.every((r) => r.severity === "critical")).toBe(true);
    expect(critical.total).toBe(n(all.counts.severity, "critical"));
    const hardening = (await get("state=all&rule_set=hardening-linux-l1&limit=100")).body;
    expect(hardening.total).toBe(n(all.counts.rule_set, "hardening-linux-l1"));
    expect(n(hardening.counts.rule_set, "baseline")).toBe(n(all.counts.rule_set, "baseline"));
    expect(n(hardening.counts.area, "SSH")).toBe(2);
    expect(n(hardening.counts.area, "Packages")).toBe(0);
    const ssh = (await get("state=all&area=SSH&limit=100")).body;
    expect(ids(ssh).sort()).toEqual(["harden.ssh.permit_empty_passwords", "harden.ssh.permit_root_login"]);
    expect((await get("q=SSH+allows")).body.total).toBe(2);
  });

  it("filters by assignee; unassigned and a person count open failing hosts only", async () => {
    const sam = (await get("assignee=u-sam&limit=100")).body;
    expect(sam.total).toBeGreaterThan(0);
    expect(sam.items.every((r) => r.assignee.kind !== "none")).toBe(true);
    const unassigned = (await get("state=all&assignee=unassigned&limit=100")).body;
    expect(row(unassigned, "harden.files.passwd")).toBeUndefined();
    expect(unassigned.total).toBe(unassigned.counts.state.find((c) => c.value === "all")?.count);
    // me is the signed-in analyst
    const me = await get("assignee=me&limit=100", "analyst");
    expect(me.body.total).toBe(me.body.counts.assignee.me);
    expect(me.body.total).toBeGreaterThan(0);
  });

  it("sorts worst first, then most failing, pages and breaks ties by key", async () => {
    const full = (await get("state=all&limit=100")).body;
    const rank = ["critical", "high", "medium", "low", "info"];
    const sev = full.items.map((r) => rank.indexOf(r.severity ?? "info"));
    expect(sev).toEqual([...sev].sort((a, b) => a - b));
    const byFailing = (await get("state=all&sort=failing&dir=asc&limit=100")).body.items.map((r) => r.failing);
    expect(byFailing).toEqual([...byFailing].sort((a, b) => a - b));
    const since = (await get("state=all&sort=since&dir=asc&limit=100")).body;
    expect(since.items.at(-1)?.since).toBeNull();
    const second = (await get("state=all&limit=1&offset=1")).body;
    expect(ids(second)).toEqual([full.items[1]?.rule_id]);
    expect(second.total).toBe(full.total);
  });

  it("keeps a team lead to their groups", async () => {
    const admin = (await get("state=all&limit=100")).body;
    const lead = await get("state=all&limit=100", "team_lead");
    expect(lead.status).toBe(200);
    expect(lead.body.total).toBeGreaterThan(0);
    const ssh = (id: Body) => row(id, "port.ssh.exposed");
    expect((ssh(lead.body)?.failing ?? 0) + (ssh(lead.body)?.passing ?? 0)).toBeLessThan((ssh(admin)?.failing ?? 0) + (ssh(admin)?.passing ?? 0));
  });

  it("answers a host filter with that host's checks", async () => {
    const one = (await get("host=agent-00001&state=all&limit=100")).body;
    expect(row(one, "harden.accounts.empty_password")).toMatchObject({ failing: 1, passing: 0 });
    expect(one.items.every((r) => r.failing + r.passing === 1)).toBe(true);
  });

  it("agrees with the host page: the same open failing checks for one seeded host", async () => {
    const server = createDemoServer({ persona: "admin" });
    const summary = (await (await server.handle("GET", "/api/v1/hosts/agent-00001/summary", undefined)).json()) as
      { host: { status: string }; tiles: { compliance_failing: number }; top_failing: { items: { rule_set_id: string; rule_id: string }[] } };
    const list = (await (await server.handle("GET", `${URL}?host=agent-00001&limit=100`, undefined)).json()) as CheckList;
    const listed = list.items.map((i) => `${i.rule_set_id}/${i.rule_id}`);
    // The host page counts findings of any host; the list needs an active one (host 1 is).
    expect(summary.host.status).toBe("online"); // the demo is seeded, so host 1 is always online
    expect(summary.tiles.compliance_failing).toBe(list.total);
    for (const i of summary.top_failing.items) expect(listed).toContain(`${i.rule_set_id}/${i.rule_id}`);
    expect(listed).toContain("hardening-linux-l1/harden.ssh.permit_root_login");
    expect(listed).toContain("site/site.change_window.exceeded");
    expect(listed).not.toContain("hardening-linux-l1/harden.kernel.aslr");
  });

  it("bulk on a check row changes only open, failing pairs (compliance.rs)", async () => {
    const server = createDemoServer({ persona: "admin" });
    type Done = { changed: number; skipped: { id: string; reason: string }[] };
    const bulk = async (body: Record<string, unknown>) => (await (await server.handle("POST", "/api/v1/compliance/bulk", body)).json()) as Done;
    const set = "hardening-linux-l1";
    const row = (rule: string, extra: Record<string, unknown> = {}) => ({ rule_set_id: set, rule_id: rule, ...extra });
    // aslr: agent-00001's finding has ended, so only agent-00002 is reached.
    expect(await bulk({ action: "assign", assignee: "sam", items: [row("harden.kernel.aslr")] })).toMatchObject({ changed: 1, skipped: [] });
    // permit_empty_passwords: agent-00001 open, agent-00002 an expired acceptance (open): both change.
    expect(await bulk({ action: "state", state: "mitigated", note: "fixed", items: [row("harden.ssh.permit_empty_passwords")] })).toMatchObject({ changed: 2, skipped: [] });
    // permit_root_login: agent-00004 (mitigated), -05 (accepted, not expired) and -07 are left alone.
    expect(await bulk({ action: "assign", assignee: "sam", items: [row("harden.ssh.permit_root_login")] })).toMatchObject({ changed: 2, skipped: [] });
    // With the Host chip, a closed pair says "not open" (and a reopen is unchanged: named pairs change).
    const chip = await bulk({ action: "state", state: "false_positive", note: "lab", items: [row("harden.ssh.permit_root_login", { agent_id: "agent-00004", open_only: true })] });
    expect(chip).toMatchObject({ changed: 0, skipped: [{ id: `agent-00004/${set}/harden.ssh.permit_root_login`, reason: "not open" }] });
    expect((await bulk({ action: "state", state: "open", items: [row("harden.ssh.permit_root_login", { agent_id: "agent-00004", open_only: true })] })).changed).toBe(1);
    // Nothing open is left on the closed-out row.
    expect(await bulk({ action: "assign", assignee: "sam", items: [row("harden.ssh.permit_empty_passwords")] })).toMatchObject({ changed: 0, skipped: [{ id: `${set}/harden.ssh.permit_empty_passwords`, reason: "not open" }] });
    // Add to case from a row takes failing pairs only: aslr's ended agent-00001 stays out, agent-00002 goes in.
    expect(await bulk({ action: "case", new_case_title: "aslr", items: [row("harden.kernel.aslr")] })).toMatchObject({ changed: 1, skipped: [] });
    expect((await server.handle("POST", "/api/v1/alarms/bulk", { action: "assign", assignee: null, items: [{ id: "1", open_only: true }] })).status).toBe(400);
  });
});
