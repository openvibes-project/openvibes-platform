import { afterEach, describe, expect, it, vi } from "vitest";

import type { CaseDetail, CaseItem, CaseSummary } from "../api/types";
import { type CaseState, type CaseWorld, createCaseStore } from "./cases";
import { buildDemoData } from "./data";
import { createDemoServer } from "./server";

type Server = ReturnType<typeof createDemoServer>;
const call = async <T = Record<string, unknown>>(server: Server, method: string, path: string, body?: unknown, headers: Record<string, string> = {}) => {
  const response = await server.handle(method, path, body, headers);
  const text = await response.text();
  return { status: response.status, etag: response.headers.get("etag"), body: (text === "" ? undefined : JSON.parse(text)) as T };
};
const list = async (server: Server, query = "status=all") => (await call<{ items: CaseSummary[] }>(server, "GET", `/api/v1/cases?${query}`)).body.items;
const get = async (server: Server, id: string) => (await call<CaseDetail>(server, "GET", `/api/v1/cases/${id}`)).body;
const day = 86_400_000;
const future = (days = 30) => new Date(Date.now() + days * day).toISOString();

/** A free alarm, host and finding to build cases from (the seed holds some). */
async function freeObjects(server: Server) {
  const held = new Set((await Promise.all((await list(server)).map((c) => get(server, c.case_id)))).flatMap((c) => c.items.map((i) => `${i.kind}:${i.ref}`)));
  const alarms = (await call<{ items: { id: string; agent_id: string; severity: string }[] }>(server, "GET", "/api/v1/alarms")).body.items;
  const alarm = alarms.find((a) => !held.has(`alarm:${a.id}`));
  const findings = (await call<{ items: { agent_id: string; rule_set_id: string; rule_id: string; severity: string }[] }>(server, "GET", "/api/v1/compliance/latest?limit=100")).body.items;
  const finding = findings.find((f) => !held.has(`finding:${f.agent_id}/${f.rule_set_id}/${f.rule_id}`));
  if (!alarm || !finding) throw new Error("demo data has no free alarm and finding");
  return { alarm, finding, findingRef: `${finding.agent_id}/${finding.rule_set_id}/${finding.rule_id}` };
}

describe("demo cases: permissions and the seed", () => {
  it("grants cases.manage to the analyst and the admin only, as the server's role table does", async () => {
    for (const [persona, manage] of [["viewer", false], ["operator", false], ["analyst", true], ["admin", true]] as const) {
      const server = createDemoServer({ persona });
      const session = (await call<{ capabilities: { permission: string }[] }>(server, "GET", "/api/v1/session")).body;
      const permissions = session.capabilities.map((c) => c.permission);
      expect(permissions.includes("cases.manage"), persona).toBe(manage);
      expect(permissions.includes("cases.read"), persona).toBe(persona === "analyst" || persona === "admin");
    }
  });

  it("refuses without the permission, with problem details", async () => {
    const viewer = createDemoServer({ persona: "viewer" });
    expect((await call(viewer, "GET", "/api/v1/cases")).status).toBe(403);
    const response = await call(viewer, "POST", "/api/v1/cases", { title: "x" });
    expect(response.status).toBe(403);
    expect(response.body.code).toBe("forbidden");
  });

  it("seeds cases over real demo objects and lists open and investigating ones by default, newest change first", async () => {
    const server = createDemoServer({ persona: "admin" });
    const open = await list(server, "");
    expect(open.length).toBeGreaterThanOrEqual(3);
    expect(open.every((c) => c.status !== "closed")).toBe(true);
    expect(open.map((c) => c.updated_at)).toEqual([...open.map((c) => c.updated_at)].sort().reverse());
    const all = await list(server);
    const closedCase = all.find((c) => c.status === "closed");
    expect(closedCase).toMatchObject({ resolution: "mitigated", pending_item_count: 0 });
    expect(new Set(all.map((c) => c.number)).size).toBe(all.length);
    // Every item points at something that exists, with its title.
    for (const summary of all) {
      const detail = await get(server, summary.case_id);
      expect(detail.items.length).toBe(summary.item_count);
      for (const item of detail.items) expect(item.title, `${summary.number} ${item.kind} ${item.ref}`).toBeTruthy();
    }
  });

  it("has an SSH investigation with a host, an alarm and a finding", async () => {
    const server = createDemoServer({ persona: "admin" });
    const ssh = (await list(server)).find((c) => /SSH/.test(c.title));
    if (!ssh) throw new Error("no SSH case");
    const detail = await get(server, ssh.case_id);
    expect(detail.items.map((i) => i.kind).sort()).toEqual(["alarm", "compliance_finding", "host"]);
    expect(detail.pending_item_count).toBe(2);
    expect(detail.events.map((e) => e.kind)).toContain("note");
  });

  it("filters by status, severity, assignee and text", async () => {
    const server = createDemoServer({ persona: "analyst" });
    expect((await list(server, "status=closed")).every((c) => c.status === "closed")).toBe(true);
    expect((await list(server, "status=investigating")).every((c) => c.status === "investigating")).toBe(true);
    expect((await list(server, "severity=critical")).every((c) => c.severity === "critical")).toBe(true);
    const mine = await list(server, "assignee=me");
    expect(mine.length).toBeGreaterThan(0);
    expect(mine.every((c) => c.assignee?.username === "sam")).toBe(true);
    const nobody = await list(server, "assignee=none");
    expect(nobody.length).toBeGreaterThan(0);
    expect(nobody.every((c) => c.assignee === null)).toBe(true);
    const first = (await list(server))[0];
    expect((await list(server, `q=${encodeURIComponent(`C-${first?.number}`)}`)).map((c) => c.number)).toContain(first?.number);
    expect(await list(server, "q=no-such-case-anywhere")).toEqual([]);
    for (const query of ["status=bad", "severity=urgent"]) expect((await call(server, "GET", `/api/v1/cases?${query}`)).status).toBe(400);
  });

  it("pages with the shared cursor", async () => {
    const server = createDemoServer({ persona: "admin" });
    const first = (await call<{ items: unknown[]; next_cursor: string | null }>(server, "GET", "/api/v1/cases?status=all&limit=2")).body;
    expect(first.items).toHaveLength(2);
    const second = (await call<{ items: unknown[] }>(server, "GET", `/api/v1/cases?status=all&limit=2&cursor=${String(first.next_cursor)}`)).body;
    expect(second.items.length).toBeGreaterThan(0);
  });

  it("answers an unknown or malformed case with the same 404", async () => {
    const server = createDemoServer({ persona: "admin" });
    for (const id of ["nope", "3f2f6b9e-0000-4000-8000-000000000000"]) {
      const response = await call(server, "GET", `/api/v1/cases/${id}`);
      expect(response.status).toBe(404);
      expect(response.body.code).toBe("case_not_found");
    }
  });

  it("lists who can be assigned: users holding cases.read, for those who manage", async () => {
    const server = createDemoServer({ persona: "analyst" });
    const users = (await call<{ items: { username: string }[] }>(server, "GET", "/api/v1/cases/assignees")).body.items.map((u) => u.username);
    expect(users.sort()).toEqual(["admin", "sam"]);
  });
});

describe("demo cases: creating and changing", () => {
  it("creates a case with items, with the highest item severity, an ETag and a timeline", async () => {
    const server = createDemoServer({ persona: "analyst" });
    const { alarm, finding, findingRef } = await freeObjects(server);
    const response = await call<CaseDetail>(server, "POST", "/api/v1/cases", {
      title: "  Investigate  ", items: [{ kind: "alarm", ref: alarm.id }, { kind: "compliance_finding", ref: findingRef }, { kind: "host", ref: finding.agent_id }],
    });
    expect(response.status).toBe(201);
    expect(response.etag).toBe('"1"');
    const rank = ["low", "medium", "high", "critical"];
    const expected = [alarm.severity, finding.severity].sort((a, b) => rank.indexOf(b) - rank.indexOf(a))[0];
    expect(response.body).toMatchObject({ title: "Investigate", status: "open", severity: expected, version: 1, item_count: 3, pending_item_count: 2, opened_by: { username: "sam" } });
    expect(response.body.events.map((e) => e.kind)).toEqual(["created", "item_added", "item_added", "item_added"]);
    expect((await get(server, response.body.case_id)).items.map((i) => i.kind)).toEqual(["alarm", "compliance_finding", "host"]);
  });

  it("validates the create body with field errors", async () => {
    const server = createDemoServer({ persona: "admin" });
    const refused = async (body: unknown, field: string, code: string) => {
      const response = await call<{ field_errors: { field: string; code: string }[] }>(server, "POST", "/api/v1/cases", body);
      expect(response.status, JSON.stringify(body)).toBe(422);
      expect(response.body.field_errors[0]).toMatchObject({ field, code });
    };
    await refused({ title: "   " }, "title", "invalid_title");
    await refused({ title: "x".repeat(121) }, "title", "invalid_title");
    await refused({ title: "ok", severity: "urgent" }, "severity", "invalid_severity");
    await refused({ title: "ok", assignee_user_id: "u-vic" }, "assignee_user_id", "assignee_unavailable");
    await refused({ title: "ok", items: [{ kind: "widget", ref: "1" }] }, "kind", "invalid_kind");
    await refused({ title: "ok", items: [{ kind: "alarm", ref: "abc" }] }, "ref", "invalid_ref");
    await refused({ title: "ok", items: Array.from({ length: 51 }, (_, i) => ({ kind: "alarm", ref: String(i + 1) })) }, "items", "too_many_items");
    expect((await call(server, "POST", "/api/v1/cases", { items: [] })).status).toBe(400);
    expect((await call(server, "POST", "/api/v1/cases", { title: "ok", items: [{ kind: "alarm", ref: "99999" }] })).status).toBe(404);
  });

  it("keeps an alarm, finding or vulnerability in one open case, naming the case; hosts and software can be in many", async () => {
    const server = createDemoServer({ persona: "admin" });
    const { alarm, finding } = await freeObjects(server);
    const first = (await call<CaseDetail>(server, "POST", "/api/v1/cases", { title: "A", items: [{ kind: "alarm", ref: alarm.id }, { kind: "host", ref: finding.agent_id }] })).body;
    const clash = await call(server, "POST", "/api/v1/cases", { title: "B", items: [{ kind: "alarm", ref: alarm.id }] });
    expect(clash.status).toBe(409);
    expect(clash.body).toMatchObject({ code: "item_in_case", case_number: first.number });
    const second = (await call<CaseDetail>(server, "POST", "/api/v1/cases", { title: "B" })).body;
    const again = await call(server, "POST", `/api/v1/cases/${second.case_id}/items`, { kind: "alarm", ref: alarm.id });
    expect(again.status).toBe(409);
    expect(again.body.case_number).toBe(first.number);
    expect((await call(server, "POST", `/api/v1/cases/${second.case_id}/items`, { kind: "host", ref: finding.agent_id })).status).toBe(201);
    expect((await call(server, "POST", `/api/v1/cases/${second.case_id}/items`, { kind: "host", ref: finding.agent_id })).body.code).toBe("item_already_in_case");
    const found = (await call<{ items: { case: CaseSummary }[] }>(server, "GET", `/api/v1/cases/for-item?kind=host&ref=${finding.agent_id}`)).body.items.map((i) => i.case.number);
    expect(found).toEqual(expect.arrayContaining([first.number, second.number]));
    const alarmHolder = (await call<{ items: { case: CaseSummary }[] }>(server, "GET", `/api/v1/cases/for-item?kind=alarm&ref=${alarm.id}`)).body.items;
    expect(alarmHolder.map((i) => i.case.number)).toEqual([first.number]);
    expect((await call(server, "GET", "/api/v1/cases/for-item?kind=alarm")).status).toBe(400);
    expect((await call(server, "GET", "/api/v1/cases/for-item?kind=alarm&ref=x")).status).toBe(422);
  });

  it("replaces fields with If-Match: 428 without it, 412 when stale, a new version otherwise", async () => {
    const server = createDemoServer({ persona: "analyst" });
    const made = (await call<CaseDetail>(server, "POST", "/api/v1/cases", { title: "Edit me", severity: "low" })).body;
    const fields = { title: "Edited", severity: "high", status: "investigating", assignee_user_id: "u-admin" };
    expect((await call(server, "PUT", `/api/v1/cases/${made.case_id}`, fields)).status).toBe(428);
    expect((await call(server, "PUT", `/api/v1/cases/${made.case_id}`, fields, { "If-Match": "abc" })).status).toBe(400);
    expect((await call(server, "PUT", `/api/v1/cases/${made.case_id}`, fields, { "If-Match": '"7"' })).status).toBe(412);
    const saved = await call<CaseDetail>(server, "PUT", `/api/v1/cases/${made.case_id}`, fields, { "If-Match": '"1"' });
    expect(saved.status).toBe(200);
    expect(saved.etag).toBe('"2"');
    expect(saved.body).toMatchObject({ title: "Edited", severity: "high", status: "investigating", version: 2, assignee: { username: "admin" } });
    expect(saved.body.events.map((e) => e.kind)).toEqual(["created", "assigned", "severity", "status"]);
    // The same values again change nothing, not even the version.
    const same = await call<CaseDetail>(server, "PUT", `/api/v1/cases/${made.case_id}`, fields, { "If-Match": '"2"' });
    expect(same.body.version).toBe(2);
    expect(same.body.events).toHaveLength(4);
    const cleared = await call<CaseDetail>(server, "PUT", `/api/v1/cases/${made.case_id}`, { ...fields, assignee_user_id: null }, { "If-Match": '"2"' });
    expect(cleared.body.assignee).toBeNull();
    expect((await call(server, "PUT", `/api/v1/cases/${made.case_id}`, { ...fields, assignee_user_id: "u-vic" }, { "If-Match": '"3"' })).status).toBe(422);
    expect((await call(server, "PUT", `/api/v1/cases/${made.case_id}`, { ...fields, status: "paused" }, { "If-Match": '"3"' })).status).toBe(422);
    expect((await call(server, "PUT", `/api/v1/cases/${made.case_id}`, { ...fields, resolution: "mitigated" }, { "If-Match": '"3"' })).body.field_errors).toBeDefined();
  });

  it("adds notes without moving the version, and removes items from an open case", async () => {
    const server = createDemoServer({ persona: "analyst" });
    const { alarm } = await freeObjects(server);
    const made = (await call<CaseDetail>(server, "POST", "/api/v1/cases", { title: "Notes", items: [{ kind: "alarm", ref: alarm.id }] })).body;
    const note = await call<{ kind: string; body: string; actor: { username: string } }>(server, "POST", `/api/v1/cases/${made.case_id}/notes`, { body: "Looked at the process tree." });
    expect(note.status).toBe(201);
    expect(note.body).toMatchObject({ kind: "note", body: "Looked at the process tree.", actor: { username: "sam" } });
    expect((await call(server, "POST", `/api/v1/cases/${made.case_id}/notes`, { body: "  " })).status).toBe(422);
    const after = await get(server, made.case_id);
    expect(after.version).toBe(1);
    const item = after.items[0] as CaseItem;
    expect((await call(server, "DELETE", `/api/v1/cases/${made.case_id}/items/${item.item_id}`)).status).toBe(204);
    expect((await call(server, "DELETE", `/api/v1/cases/${made.case_id}/items/${item.item_id}`)).body.code).toBe("item_not_found");
    const final = await get(server, made.case_id);
    expect(final.items).toEqual([]);
    expect(final.events.map((e) => e.kind)).toEqual(["created", "item_added", "note", "item_removed"]);
    // The alarm is free again.
    expect((await call(server, "POST", `/api/v1/cases/${made.case_id}/items`, { kind: "alarm", ref: alarm.id })).status).toBe(201);
  });
});

describe("demo cases: outcomes and closing", () => {
  const triage = async (server: Server, alarmId: string, state: string) => {
    const alarm = (await call<{ triage: { version: number } }>(server, "GET", `/api/v1/alarms/${alarmId}`)).body;
    return call(server, "PUT", `/api/v1/alarms/${alarmId}/triage`, { state, note: "done" }, { "If-Match": `"${alarm.triage.version}"` });
  };

  it("takes outcomes by the evidence rules", async () => {
    const server = createDemoServer({ persona: "analyst" });
    const { alarm, finding, findingRef } = await freeObjects(server);
    const made = (await call<CaseDetail>(server, "POST", "/api/v1/cases", {
      title: "Outcomes", items: [{ kind: "alarm", ref: alarm.id }, { kind: "compliance_finding", ref: findingRef }, { kind: "host", ref: finding.agent_id }],
    })).body;
    const [alarmItem, , hostItem] = made.items as [CaseItem, CaseItem, CaseItem];
    const outcome = (item: CaseItem, body: unknown) => call<CaseItem & { field_errors?: { field: string; code: string }[] }>(server, "PUT", `/api/v1/cases/${made.case_id}/items/${item.item_id}/outcome`, body);
    expect(alarmItem.evidence_gone).toBe(false);
    expect((await outcome(alarmItem, { outcome: "resolved" })).body).toMatchObject({ code: "evidence_present" });
    expect((await outcome(alarmItem, { outcome: "false_positive" })).body.field_errors?.[0]).toMatchObject({ field: "note", code: "note_required" });
    expect((await outcome(alarmItem, { outcome: "accepted_risk", note: "  " })).status).toBe(422);
    expect((await outcome(alarmItem, { outcome: "fixed" })).status).toBe(422);
    expect((await outcome(hostItem, { outcome: "false_positive", note: "n" })).body.field_errors?.[0]).toMatchObject({ code: "outcome_not_applicable" });
    expect((await outcome({ ...alarmItem, item_id: "missing" }, { outcome: "false_positive", note: "n" })).body).toMatchObject({ code: "item_not_found" });
    const marked = await outcome(alarmItem, { outcome: "false_positive", note: "Health check." });
    expect(marked.status).toBe(200);
    expect(marked.body).toMatchObject({ outcome: "false_positive", outcome_note: "Health check." });
    expect((await get(server, made.case_id)).pending_item_count).toBe(1);
    const cleared = await outcome(alarmItem, { outcome: null });
    expect(cleared.body.outcome).toBeNull();
    expect((await get(server, made.case_id)).pending_item_count).toBe(2);
    // Mitigating the alarm elsewhere is the evidence that lets it be resolved.
    expect((await triage(server, alarm.id, "investigating")).status).toBe(200);
    expect((await triage(server, alarm.id, "mitigated")).status).toBe(200);
    const detail = await get(server, made.case_id);
    expect(detail.items.find((i) => i.item_id === alarmItem.item_id)?.evidence_gone).toBe(true);
    expect((await outcome(alarmItem, { outcome: "resolved" })).body.outcome).toBe("resolved");
  });

  it("closes only with a resolution, a note, a future date for accepted risk and an outcome on every item", async () => {
    const server = createDemoServer({ persona: "analyst" });
    const { alarm, finding, findingRef } = await freeObjects(server);
    const made = (await call<CaseDetail>(server, "POST", "/api/v1/cases", {
      title: "Close me", items: [{ kind: "alarm", ref: alarm.id }, { kind: "compliance_finding", ref: findingRef }, { kind: "host", ref: finding.agent_id }],
    })).body;
    const url = `/api/v1/cases/${made.case_id}`;
    const base = { title: "Close me", severity: made.severity, status: "closed", assignee_user_id: null };
    const put = (body: Record<string, unknown>, version: number) => call<CaseDetail & { field_errors?: { field: string; code: string }[] }>(server, "PUT", url, { ...base, ...body }, { "If-Match": `"${version}"` });
    const code = async (body: Record<string, unknown>) => (await put(body, 1)).body.field_errors?.[0]?.code;
    expect(await code({})).toBe("resolution_required");
    expect(await code({ resolution: "fixed", resolution_note: "n" })).toBe("invalid_resolution");
    expect(await code({ resolution: "mitigated" })).toBe("resolution_note_required");
    expect(await code({ resolution: "mitigated", resolution_note: "   " })).toBe("resolution_note_required");
    expect(await code({ resolution: "accepted_risk", resolution_note: "n" })).toBe("accepted_until_required");
    expect(await code({ resolution: "accepted_risk", resolution_note: "n", accepted_until: future(-1) })).toBe("accepted_until_past");
    expect(await code({ resolution: "mitigated", resolution_note: "n", accepted_until: future() })).toBe("accepted_until_not_allowed");
    expect(await code({ resolution: "mitigated", resolution_note: "n", accepted_until: "tomorrow" })).toBe("invalid_timestamp");
    expect(await code({ status: "open", resolution: "mitigated", resolution_note: "n" })).toBe("resolution_not_allowed");
    // The alarm and the finding still need an outcome; the host does not.
    const stuck = await put({ resolution: "mitigated", resolution_note: "Fixed." }, 1);
    expect(stuck.status).toBe(409);
    expect(stuck.body).toMatchObject({ code: "items_unresolved" });
    for (const item of made.items.filter((i) => i.kind !== "host")) {
      await call(server, "PUT", `${url}/items/${item.item_id}/outcome`, { outcome: "accepted_risk", note: "Known." });
    }
    const done = await put({ resolution: "accepted_risk", resolution_note: "Known and watched.", accepted_until: future() }, 1);
    expect(done.status).toBe(200);
    expect(done.body).toMatchObject({ status: "closed", resolution: "accepted_risk", resolution_note: "Known and watched.", version: 2, pending_item_count: 0 });
    expect(done.body.closed_at).toBeTruthy();
    expect(done.body.items.every((i) => !i.active)).toBe(true);
    expect(done.body.events.at(-1)).toMatchObject({ kind: "resolved", body: "Known and watched." });
    // Closing frees the items for another case.
    const reuse = await call(server, "POST", "/api/v1/cases", { title: "Again", items: [{ kind: "alarm", ref: alarm.id }] });
    expect(reuse.status).toBe(201);
    // A closed case keeps how it ended; items and outcomes are locked, notes are not.
    expect((await call(server, "POST", `${url}/items`, { kind: "host", ref: finding.agent_id })).body).toMatchObject({ code: "case_closed" });
    expect((await call(server, "DELETE", `${url}/items/${made.items[2]?.item_id}`)).status).toBe(409);
    expect((await call(server, "PUT", `${url}/items/${made.items[0]?.item_id}/outcome`, { outcome: null })).body.code).toBe("case_closed");
    expect((await call(server, "PUT", url, { ...base, resolution: "mitigated", resolution_note: "Changed my mind." }, { "If-Match": '"2"' })).body).toMatchObject({ code: "case_closed" });
    expect((await call(server, "POST", `${url}/notes`, { body: "Still watching." })).status).toBe(201);
    // Reopening is refused while an item sits in another open case, and works once it does not.
    const blocked = await call(server, "PUT", url, { ...base, status: "open" }, { "If-Match": '"2"' });
    expect(blocked.status).toBe(409);
    expect(blocked.body).toMatchObject({ code: "item_in_case", case_number: (reuse.body as unknown as CaseDetail).number });
    await call(server, "DELETE", `/api/v1/cases/${(reuse.body as unknown as CaseDetail).case_id}/items/${(reuse.body as unknown as CaseDetail).items[0]?.item_id}`);
    const reopened = await call<CaseDetail>(server, "PUT", url, { ...base, status: "open" }, { "If-Match": '"2"' });
    expect(reopened.status).toBe(200);
    expect(reopened.body).toMatchObject({ status: "open", resolution: null, resolution_note: null, closed_at: null, version: 3 });
    expect(reopened.body.items.every((i) => i.active)).toBe(true);
    expect(reopened.body.events.at(-1)).toMatchObject({ kind: "reopened", detail: { reason: "manual" } });
  });

  it("closes over a resolved item while its evidence stays gone", async () => {
    const server = createDemoServer({ persona: "analyst" });
    const { alarm } = await freeObjects(server);
    const made = (await call<CaseDetail>(server, "POST", "/api/v1/cases", { title: "Back again", items: [{ kind: "alarm", ref: alarm.id }] })).body;
    await triage(server, alarm.id, "investigating");
    await triage(server, alarm.id, "mitigated");
    const item = made.items[0] as CaseItem;
    expect((await call(server, "PUT", `/api/v1/cases/${made.case_id}/items/${item.item_id}/outcome`, { outcome: "resolved" })).status).toBe(200);
    // The demo's alarm workflow does not reopen a mitigated alarm, so the evidence stays gone and the case closes.
    const closing = await call<CaseDetail>(server, "PUT", `/api/v1/cases/${made.case_id}`, { title: "Back again", severity: made.severity, status: "closed", resolution: "mitigated", resolution_note: "Gone." }, { "If-Match": '"1"' });
    expect(closing.status).toBe(200);
  });

  it("reopens a case when its accepted risk runs out, and clears the accepted outcomes", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const server = createDemoServer({ persona: "admin" });
      const { alarm } = await freeObjects(server);
      const made = (await call<CaseDetail>(server, "POST", "/api/v1/cases", { title: "Accepted", items: [{ kind: "alarm", ref: alarm.id }] })).body;
      const url = `/api/v1/cases/${made.case_id}`;
      await call(server, "PUT", `${url}/items/${made.items[0]?.item_id}/outcome`, { outcome: "accepted_risk", note: "For now." });
      const until = future(10);
      const closed = await call<CaseDetail>(server, "PUT", url, { title: "Accepted", severity: made.severity, status: "closed", resolution: "accepted_risk", resolution_note: "For now.", accepted_until: until }, { "If-Match": '"1"' });
      expect(closed.status).toBe(200);
      vi.setSystemTime(Date.now() + 11 * day);
      const reopened = await get(server, made.case_id);
      expect(reopened).toMatchObject({ status: "open", resolution: null, accepted_until: null, pending_item_count: 1 });
      expect(reopened.items[0]).toMatchObject({ outcome: null, active: true });
      expect(reopened.events.at(-1)).toMatchObject({ kind: "reopened", actor: null, detail: { reason: "accepted_risk_expired" } });
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("demo cases: scope", () => {
  /** A store whose viewer sees only the hosts in `visible`. */
  function scoped(visible: string[], persisted?: { value: unknown }) {
    const me = { user_id: "u-ola", username: "ola", display_name: "Ola" };
    const state: CaseState = { v: 2, next_number: 1, next_event: 1, cases: [], items: [], events: [] };
    const world: CaseWorld = {
      me, people: [me, { user_id: "u-sam", username: "sam", display_name: "Sam" }], assignable: ["u-ola", "u-sam"],
      canSee: (id) => visible.includes(id), hostname: (id) => id,
      facts: (kind, ref) => kind === "host" ? { agent_id: ref, title: ref, severity: null, gone: false }
        : kind === "alarm" ? { agent_id: ref === "1" ? "agent-a" : "agent-b", title: `alarm ${ref}`, severity: "high", gone: false } : undefined,
      audit: () => undefined,
    };
    const store = createCaseStore(world, () => state, persisted ? { load: () => persisted.value, save: (s) => { persisted.value = JSON.parse(JSON.stringify(s)); } } : undefined);
    return { store, state };
  }

  it("shows a user only cases with an item they can see, with only those items, counts and timeline entries", () => {
    const { store, state } = scoped(["agent-a", "agent-b"]);
    const both = store.create({ title: "Both", items: [{ kind: "alarm", ref: "1" }, { kind: "alarm", ref: "2" }] }).body as CaseDetail;
    // The same data seen from a narrower scope.
    const narrow = scoped(["agent-a"]);
    narrow.state.cases.push(...state.cases);
    narrow.state.items.push(...state.items);
    narrow.state.events.push(...state.events);
    narrow.state.next_number = state.next_number;
    const seen = narrow.store.get(both.case_id).body as CaseDetail;
    expect(seen.items.map((i) => i.ref)).toEqual(["1"]);
    expect(seen).toMatchObject({ item_count: 1, pending_item_count: 1 });
    expect(seen.events.filter((e) => e.kind === "item_added")).toHaveLength(1);
    expect((narrow.store.list(new URLSearchParams("status=all")).body as CaseSummary[]).map((c) => c.number)).toEqual([both.number]);
    // Someone who sees none of its items gets the same 404 as for a case that is not there.
    const outside = scoped(["agent-z"]);
    outside.state.cases.push(...state.cases.map((c) => ({ ...c, opened_by_user_id: "u-sam" })));
    outside.state.items.push(...state.items);
    expect(outside.store.get(both.case_id).status).toBe(404);
    expect(outside.store.list(new URLSearchParams("status=all")).body).toEqual([]);
    // They see it again when it is assigned to them.
    for (const c of outside.state.cases) c.assignee_user_id = "u-ola";
    expect(outside.store.get(both.case_id).status).toBe(200);
  });

  it("answers an item outside the scope like one that does not exist, and does not name hidden cases", () => {
    const { store } = scoped(["agent-a"]);
    expect(store.create({ title: "x", items: [{ kind: "alarm", ref: "2" }] }).status).toBe(404);
    expect(store.create({ title: "x", items: [{ kind: "alarm", ref: "404" }] }).status).toBe(404);
    expect(store.create({ title: "x", items: [{ kind: "host", ref: "agent-b" }] }).status).toBe(404);
  });

  it("refuses to close over hidden items that have no outcome", () => {
    const { store, state } = scoped(["agent-a", "agent-b"]);
    const made = store.create({ title: "Both", items: [{ kind: "alarm", ref: "1" }, { kind: "alarm", ref: "2" }] }).body as CaseDetail;
    const narrow = scoped(["agent-a"]);
    narrow.state.cases.push(...state.cases);
    narrow.state.items.push(...state.items);
    const visible = made.items[0] as CaseItem;
    expect(narrow.store.setOutcome(made.case_id, visible.item_id, { outcome: "false_positive", note: "n" }).status).toBe(200);
    const close = narrow.store.update(made.case_id, { title: "Both", severity: "high", status: "closed", resolution: "mitigated", resolution_note: "n" }, '"1"');
    expect(close.status).toBe(409);
    expect((close.body as { code: string }).code).toBe("hidden_items_unresolved");
  });

  it("keeps its state in the persistence it is given and loads it back", () => {
    const saved = { value: undefined as unknown };
    const first = scoped(["agent-a"], saved);
    const made = first.store.create({ title: "Remembered", items: [{ kind: "host", ref: "agent-a" }] }).body as CaseDetail;
    const second = scoped(["agent-a"], saved);
    expect((second.store.get(made.case_id).body as CaseDetail).title).toBe("Remembered");
    expect((second.store.create({ title: "Next" }).body as CaseDetail).number).toBe(made.number + 1);
  });
});

describe("demo cases data", () => {
  it("is built from objects in the demo data", () => {
    const data = buildDemoData(Date.parse("2026-10-04T12:00:00Z"));
    expect(data.access.roles.find((r) => r.role_id === "analyst")?.permissions).toContain("cases.manage");
    expect(data.access.roles.find((r) => r.role_id === "admin")?.permissions).toContain("cases.manage");
    expect(data.access.roles.find((r) => r.role_id === "viewer")?.permissions).not.toContain("cases.read");
    // The server's admin holds every permission the other roles do.
    const admin = data.access.roles.find((r) => r.role_id === "admin")?.permissions ?? [];
    for (const role of data.access.roles) expect(admin, role.role_id).toEqual(expect.arrayContaining(role.permissions));
  });
});

afterEach(() => vi.useRealTimers());
