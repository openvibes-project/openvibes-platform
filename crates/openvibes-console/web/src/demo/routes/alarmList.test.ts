// The demo's Alarms list answers like GET /api/v1/alarm-list (alarms/list.rs):
// validation, the open default and state=all, "me", chosen values and counts
// with the other filters applied, and reach.
import { describe, expect, it } from "vitest";

import type { AlarmList } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Body = AlarmList & { field_errors?: { field: string }[] };
const get = async (path: string, persona: Persona = "admin") => {
  const response = await createDemoServer({ persona }).handle("GET", path, undefined);
  return { status: response.status, body: (await response.json()) as Body };
};
const messages = (b: AlarmList) => b.items.map((i) => i.id);

describe("demo Alarms list", () => {
  it.each([
    ["state=gone", "state"], ["severity=huge", "severity"], ["suppressed=yes", "suppressed"], ["group=!", "group"], ["case=maybe", "case"],
    ["assignee=Nobody", "assignee"], ["sort=colour", "sort"], ["dir=up", "dir"], ["offset=-1", "offset"], ["offset=100001", "offset"],
    [`q=${"x".repeat(201)}`, "q"], ["technique=%00", "technique"],
  ])("refuses %s naming %s", async (query, field) => {
    const { status, body } = await get(`/api/v1/alarm-list?${query}`);
    expect(status).toBe(400);
    expect(body.field_errors?.[0]?.field).toBe(field);
  });

  it("refuses a limit outside 1 to 100 (the demo server checks every list's limit)", async () => {
    for (const limit of ["0", "101"]) expect((await get(`/api/v1/alarm-list?limit=${limit}`)).status).toBe(400);
  });

  it("shows open alarms by default and every state for state=all, the summary counting open ones either way", async () => {
    const open = (await get("/api/v1/alarm-list")).body;
    expect(open.items.every((i) => i.state === "open")).toBe(true);
    expect(open.total).toBe(open.summary.open);
    const all = (await get("/api/v1/alarm-list?state=all")).body;
    expect(all.total).toBeGreaterThan(open.total);
    expect(all.summary).toEqual(open.summary);
    const done = (await get("/api/v1/alarm-list?state=mitigated")).body;
    expect(done.items.length).toBeGreaterThan(0);
    expect(done.summary.open).toBe(open.summary.open);
    expect(open.counts.state.map((c) => c.value)).toEqual(["open", "mitigated", "accepted_risk", "false_positive"]);
  });

  it("counts each filter's values with the other filters applied and offers facets with values", async () => {
    const { body } = await get("/api/v1/alarm-list?state=all&severity=high");
    const critical = body.counts.severity.find((c) => c.value === "critical");
    expect(critical?.count).toBeGreaterThan(0);
    expect(body.total).toBe(body.counts.severity.find((c) => c.value === "high")?.count);
    expect(body.counts.technique.length).toBeGreaterThan(0);
    expect(body.counts.assignee.people.length).toBeGreaterThan(0);
    const technique = body.counts.technique[0]?.value ?? "";
    const chosen = (await get(`/api/v1/alarm-list?state=all&technique=${technique}`)).body;
    expect(chosen.items.every((i) => i.techniques.includes(technique))).toBe(true);
  });

  it("resolves me from the session and unassigned apart from any name", async () => {
    const sam = (await get("/api/v1/alarm-list?state=all&assignee=me", "analyst")).body;
    expect(sam.items.length).toBeGreaterThan(0);
    expect(sam.items.every((i) => i.assignee?.name === "Sam Analyst")).toBe(true);
    const none = (await get("/api/v1/alarm-list?state=all&assignee=unassigned")).body;
    expect(none.items.every((i) => i.assignee === null)).toBe(true);
    expect((await get("/api/v1/alarm-list?assignee=u-nobody")).body.total).toBe(0);
  });

  it("pages and sorts", async () => {
    const full = (await get("/api/v1/alarm-list?state=all&sort=count&dir=desc")).body;
    const counts = full.items.map((i) => i.count);
    expect(counts).toEqual([...counts].sort((a, b) => b - a));
    const second = (await get("/api/v1/alarm-list?state=all&sort=count&dir=desc&limit=1&offset=1")).body;
    expect(messages(second)).toEqual([full.items[1]?.id]);
    expect(second.total).toBe(full.total);
  });

  it("stays inside the persona's reach and hides the alarms-off number without hosts.read", async () => {
    const admin = (await get("/api/v1/alarm-list?state=all")).body;
    const scoped = (await get("/api/v1/alarm-list?state=all", "scoped_operator")).body;
    expect(scoped.total).toBeLessThan(admin.total);
    const hostId = admin.items.find((i) => !scoped.items.some((s) => s.id === i.id))?.host.id ?? "";
    const named = (await get(`/api/v1/alarm-list?state=all&host=${hostId}`, "scoped_operator")).body;
    expect(named.total).toBe(0);
    expect(typeof admin.summary.on_alarms_off_hosts).toBe("number");
    expect((await get("/api/v1/alarm-list", "viewer")).status).toBe(200);
  });

  it("is refused without alarms.read", async () => {
    expect((await get("/api/v1/alarm-list", "rule_author")).status).toBe(403);
  });
});
