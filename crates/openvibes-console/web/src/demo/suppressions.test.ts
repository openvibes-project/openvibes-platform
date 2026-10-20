// The demo's alarm suppressions with approval, against the real API's
// semantics (src/alarms/suppressions.rs, suppression_decisions.rs): states,
// refusal codes, per-row flags, options and close-on-activation. Storage is
// shared across personas, as in the browser.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AlarmSuppression, AlarmSuppressionOptions } from "../api/types";
import type { Persona } from "./personas";
import { createDemoServer } from "./server";

type Server = ReturnType<typeof createDemoServer>;
const LIST = "/api/v1/alarm-suppressions";
// Alarm 9000 runs on a Pilot host (the team lead's reach); 9001 and 9002 do not.
const PILOT_ALARM = "9000";
/** The seed's own active suppression (it closed the seed's suppressed alarm). */
const SEED = "900";

async function call<T = Record<string, unknown>>(server: Server, method: string, url: string, body?: unknown) {
  const response = await server.handle(method, url, body);
  return { status: response.status, body: (response.status === 204 ? {} : await response.json()) as T };
}
const as = (persona: Persona) => createDemoServer({ persona });
const ask = (server: Server, more: Record<string, unknown> = {}) =>
  call<AlarmSuppression>(server, "POST", LIST, { alarm_id: PILOT_ALARM, what: "program", where: { kind: "host" }, for_days: 7, reason: "health check", ...more });
const rows = async (server: Server) => (await call<{ items: AlarmSuppression[] }>(server, "GET", LIST)).body.items;
const alarm = async (server: Server, id = PILOT_ALARM) => (await call<{ state: string; suppressed_by: string | null }>(server, "GET", `/api/v1/alarms/${id}`)).body;
const approval = async (on: boolean) => expect((await call(as("admin"), "PATCH", "/api/v1/settings/suppressions.require_approval", { value: on })).status).toBe(200);

beforeEach(() => {
  const store = new Map<string, string>();
  vi.stubGlobal("localStorage", { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v), removeItem: (k: string) => void store.delete(k) });
});
afterEach(() => { vi.unstubAllGlobals(); });

describe("demo suppressions", () => {
  it("activates at once with approval off and closes the source alarm", async () => {
    const analyst = as("analyst");
    const made = await ask(analyst);
    expect(made.status).toBe(201);
    expect(made.body).toMatchObject({ status: "active", what: "program", for_days: 7, requested_by: "Sam Analyst", alarm_id: PILOT_ALARM, can_remove: true, can_withdraw: false });
    expect(made.body.where).toMatchObject({ kind: "host", hostname: "api-01.lab.example.test" });
    expect(Date.parse(made.body.expires_at ?? "") - Date.parse(made.body.activated_at ?? "")).toBe(7 * 86_400_000);
    expect(await alarm(analyst)).toMatchObject({ state: "false_positive", suppressed_by: made.body.id });
    // Another persona's demo sees the same rows and the closed alarm.
    expect((await rows(as("admin"))).map((r) => r.id)).toContain(made.body.id);
    expect((await alarm(as("admin"))).state).toBe("false_positive");
  });

  it("waits with approval on; the requester withdraws, someone else approves", async () => {
    await approval(true);
    const analyst = as("analyst");
    const first = (await ask(analyst)).body;
    expect(first).toMatchObject({ status: "waiting", can_withdraw: true, can_decide: false, activated_at: null });
    expect((await alarm(analyst)).state).toBe("open");
    expect((await call(analyst, "POST", `${LIST}/${first.id}/withdraw`)).status).toBe(200);
    expect((await rows(analyst)).filter((r) => r.id !== SEED)).toEqual([]);
    const again = (await ask(analyst)).body;
    const waiting = (await call<{ items: AlarmSuppression[] }>(as("admin"), "GET", `${LIST}?alarm_id=${PILOT_ALARM}&state=waiting`)).body.items;
    // It would close the alarm and its two siblings on the same host (same rule and program).
    expect(waiting).toMatchObject([{ id: again.id, can_decide: true, would_close: 3 }]);
    const admin = as("admin");
    const approved = await call<AlarmSuppression>(admin, "POST", `${LIST}/${again.id}/approve`);
    expect(approved.body).toMatchObject({ status: "active", decided_by: "Alex Admin" });
    expect((await alarm(admin)).state).toBe("false_positive");
    expect((await call(admin, "POST", `${LIST}/${again.id}/approve`)).body).toMatchObject({ code: "suppression_not_waiting" });
    expect((await call(as("analyst"), "DELETE", `${LIST}/${again.id}`)).status).toBe(204);
  });

  it("answers the server's refusal codes", async () => {
    let lead = as("team_lead");
    const code = async (p: Promise<{ status: number; body: Record<string, unknown> }>) => { const r = await p; return [r.status, r.body.code, (r.body.field_errors as { field: string }[] | undefined)?.[0]?.field]; };
    expect(await code(ask(lead, { alarm_id: "9001" }))).toEqual([404, "alarm_not_found", undefined]);
    expect(await code(ask(lead, { where: { kind: "all" } }))).toEqual([403, "global_scope_required", undefined]);
    expect(await code(ask(lead, { where: { kind: "group", group_id: "grp-prod" } }))).toEqual([403, "permission_denied", undefined]);
    expect(await code(ask(lead, { reason: " " }))).toEqual([422, "invalid_suppression", "reason"]);
    expect(await code(ask(lead, { for_days: 5 }))).toEqual([422, "invalid_suppression", "for"]);
    expect(await code(ask(as("admin"), { where: { kind: "group", group_id: "grp-nope" } }))).toEqual([422, "invalid_suppression", "group"]);
    await approval(true);
    // Each persona's demo reads the settings when it starts, as a switch does.
    lead = as("team_lead");
    const own = (await ask(lead, { where: { kind: "group", group_id: "grp-pilot" } })).body as { id: string };
    expect(await code(call(lead, "POST", `${LIST}/${own.id}/approve`))).toEqual([409, "own_request", undefined]);
    const theirs = (await ask(as("analyst"), { alarm_id: "9002" })).body as { id: string };
    expect(await code(call(lead, "POST", `${LIST}/${theirs.id}/approve`))).toEqual([404, "suppression_not_found", undefined]);
    expect(await code(call(as("admin"), "POST", `${LIST}/${own.id}/reject`, {}))).toEqual([422, "invalid_suppression", "reason"]);
    expect(await code(call(as("admin"), "POST", `${LIST}/${own.id}/withdraw`))).toEqual([404, "suppression_not_found", undefined]);
    expect(await code(call(as("viewer"), "POST", LIST, {}))).toEqual([403, "forbidden", undefined]);
    const rejected = await call<AlarmSuppression>(as("admin"), "POST", `${LIST}/${own.id}/reject`, { reason: "too wide" });
    expect(rejected.body).toMatchObject({ status: "rejected", decision_reason: "too wide" });
  });

  it("drops malformed rows read back from storage", async () => {
    const made = (await ask(as("admin"))).body;
    const stored = JSON.parse(localStorage.getItem("openvibes.v2.demo.suppressions") ?? "[]") as Record<string, unknown>[];
    const bad = [null, 7, { ...stored[0], id: "x" }, { ...stored[0], id: "8", state: "odd" }, { ...stored[0], id: "9", for_days: 5 },
      { ...stored[0], id: "10", args: [1] }, { ...stored[0], id: "11", reason: null }, { ...stored[0], id: "12", agent_id: 3 }];
    localStorage.setItem("openvibes.v2.demo.suppressions", JSON.stringify([...stored, ...bad]));
    const list = await call<{ items: AlarmSuppression[] }>(as("admin"), "GET", LIST);
    expect(list.status).toBe(200);
    expect(list.body.items.map((r) => r.id)).toEqual([made.id, SEED]);
  });

  it("shows rows by reach and offers the caller's groups", async () => {
    const admin = as("admin");
    const pilot = (await ask(admin, { where: { kind: "group", group_id: "grp-pilot" } })).body;
    const prod = (await ask(admin, { alarm_id: "9002", where: { kind: "group", group_id: "grp-prod" } })).body;
    const all = (await ask(admin, { alarm_id: "9001", where: { kind: "all" } })).body;
    const seen = (await rows(as("team_lead"))).map((r) => r.id);
    expect(seen).toContain(pilot.id);
    expect(seen).toContain(all.id);
    expect(seen).not.toContain(prod.id);
    expect((await rows(as("team_lead"))).find((r) => r.id === all.id)?.can_remove).toBe(false);
    const options = (await call<AlarmSuppressionOptions>(as("team_lead"), "GET", `${LIST}/options`)).body;
    expect(options).toEqual({ require_approval: false, all_hosts: false, groups: [{ id: "grp-pilot", name: "Pilot hosts" }] });
    expect((await call<AlarmSuppressionOptions>(admin, "GET", `${LIST}/options`)).body.all_hosts).toBe(true);
  });

  it("ends a group's suppressions when the group is deleted, and counts them first", async () => {
    const admin = as("admin");
    const made = (await call<{ asset_group_id: string }>(admin, "POST", "/api/v1/host-groups", { name: "Quiet lab", kind: "manual", agent_ids: ["agent-00001"] })).body;
    const id = made.asset_group_id;
    await ask(admin, { where: { kind: "group", group_id: id } });
    const preview = (await call<{ suppressions_ended: number }>(admin, "POST", `/api/v1/host-groups/${id}/preview`, {})).body;
    expect(preview.suppressions_ended).toBe(1);
    expect((await call(admin, "DELETE", `/api/v1/host-groups/${id}?version=1`)).status).toBe(204);
    expect((await rows(admin)).filter((r) => r.where.group_id === id)).toEqual([]);
  });

  it("bulk Suppress closes every selected alarm of one rule and program, none while approval is on", async () => {
    type Row = { id: string; rule_set_id: string; rule_id: string; exe: string | null; state: string };
    // The demo's four nginx shell alarms (two hosts) share rule and program.
    const pick = async () => {
      const items = (await call<{ items: Row[] }>(as("admin"), "GET", "/api/v1/alarms?limit=100")).body.items;
      return items.filter((a) => a.rule_id === "web-server-spawns-shell" && a.exe === "/usr/bin/sh").map((a) => a.id);
    };
    const bulk = async (ids: string[]) =>
      (await call<{ changed: number; skipped: { reason: string }[] }>(as("admin"), "POST", "/api/v1/alarms/bulk", { action: "suppress", note: "noise", items: ids.map((id) => ({ id })) })).body;
    await approval(true);
    const ids = await pick();
    expect(ids).toHaveLength(4);
    const waiting = await bulk(ids);
    expect(waiting.changed).toBe(0);
    expect(waiting.skipped.map((s) => s.reason)).toEqual(Array(4).fill("Suppression requested, waiting for approval"));
    for (const id of ids) expect((await alarm(as("admin"), id)).state).toBe("open");
    await approval(false);
    const done = await bulk(ids);
    expect(done).toMatchObject({ changed: 4, skipped: [] });
    for (const id of ids) expect((await alarm(as("admin"), id)).state).toBe("false_positive");
  });

  it("closes the source alarm only when the where covers its host", async () => {
    const admin = as("admin");
    const made = (await call<{ asset_group_id: string }>(admin, "POST", "/api/v1/host-groups", { name: "Elsewhere", kind: "manual", agent_ids: ["agent-00003"] })).body;
    const elsewhere = (await ask(admin, { where: { kind: "group", group_id: made.asset_group_id } })).body;
    expect(elsewhere.status).toBe("active");
    expect((await alarm(admin)).state).toBe("open");
    await ask(admin, { where: { kind: "group", group_id: "grp-pilot" } });
    expect((await alarm(admin)).state).toBe("false_positive");
  });
});
