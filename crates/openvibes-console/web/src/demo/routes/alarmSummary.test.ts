// The demo's alarm page summary answers like GET /api/v1/alarms/{id}/summary
// (alarms/summary.rs): reach, siblings as commands seen, the last 24 hours,
// the Related card and the actions per permission on the host.
import { describe, expect, it } from "vitest";

import type { AlarmList, AlarmSummaryPage } from "../../api/types";
import type { Persona } from "../personas";
import { createDemoServer } from "../server";

type Body = AlarmSummaryPage & { code?: string };
const HOUR = 3_600_000;
const call = async (server: ReturnType<typeof createDemoServer>, id: string) => {
  const response = await server.handle("GET", `/api/v1/alarms/${id}/summary`, undefined);
  return { status: response.status, body: (await response.json()) as Body };
};
const get = (id: string, persona: Persona = "admin") => call(createDemoServer({ persona }), id);

describe("demo alarm summary", () => {
  it("answers the alarm, tiles, rule, commands, hourly and related", async () => {
    const { status, body } = await get("9000");
    expect(status).toBe(200);
    expect(body.alarm.id).toBe(9000);
    expect(body.alarm.triage.version).toBeGreaterThan(0);
    expect(body.tiles.different_commands).toBe(body.commands.length);
    expect(body.tiles.starts).toBe(body.commands.reduce((n, c) => n + c.count, 0));
    expect(body.rule.title).toBe(body.alarm.message);
    expect(body.hourly).toHaveLength(24);
    expect(body.related.host_alarms.items.every((a) => a.id !== 9000)).toBe(true);
    expect(body.related.host_vulnerabilities).not.toBeNull();
    expect(body.can).toEqual({ triage: true, assign: true, suppress: true, add_to_case: true, ask: true, export: true });
  });

  it("lists siblings only, the usual command first, and their starts in the last 24 hours", async () => {
    const server = createDemoServer();
    const now = Date.now();
    const base = server.data.alarms.find((a) => a.id === "9000");
    if (!base) throw new Error("no alarm 9000");
    const other = server.data.alarms.find((a) => a.agent_id !== base.agent_id)?.agent_id ?? "";
    const at = (ms: number) => new Date(ms).toISOString();
    const clone = (id: string, count: number, ago: number, change: Partial<typeof base> = {}) =>
      ({ ...base, id, count, last_seen: at(now - ago), first_seen: at(now - ago - HOUR), ...change,
        process: { ...base.process, args: ["sh", "-c", id] } });
    server.data.alarms.push(
      clone("9100", 50, HOUR), clone("9101", 7, 25 * HOUR),
      clone("9102", 9, HOUR, { exe: "/usr/bin/other" }), clone("9103", 9, HOUR, { parent_exe: "/usr/bin/fish" }),
      clone("9104", 9, HOUR, { agent_id: other }),
    );
    const { body } = await call(server, "9000");
    expect(body.commands.map((c) => c.id)).toEqual([9100, 9101, 9000]);
    expect(body.commands[0]?.args).toEqual(["sh", "-c", "9100"]);
    expect(body.tiles.starts).toBe(50 + 7 + base.count);
    // 9100 an hour ago; 9101, 25 hours ago, is outside the window.
    expect(body.hourly[22]).toBeGreaterThanOrEqual(50);
    expect(body.hourly.reduce((n, h) => n + h, 0)).toBe(50 + base.count);
    expect(body.related.same_rule_elsewhere.hosts).toBeGreaterThanOrEqual(1);
  });

  it("is the same 404 for an alarm out of reach as for a missing one", async () => {
    const admin = (await (await createDemoServer().handle("GET", "/api/v1/alarm-list?state=all", undefined)).json()) as AlarmList;
    const scoped = (await (await createDemoServer({ persona: "scoped_operator" }).handle("GET", "/api/v1/alarm-list?state=all", undefined)).json()) as AlarmList;
    const outside = admin.items.find((i) => !scoped.items.some((s) => s.id === i.id));
    expect(outside).toBeDefined();
    const far = await get(String(outside?.id), "scoped_operator");
    expect(far.status).toBe(404);
    expect(far.body.code).toBe("alarm_not_found");
    expect((await get("424242")).body.code).toBe("alarm_not_found");
    const near = scoped.items[0];
    if (near) {
      const { body } = await get(String(near.id), "scoped_operator");
      expect(body.commands.length).toBeGreaterThan(0);
    }
  });

  it("offers each action only with its permission, and refuses without alarms.read", async () => {
    const { body } = await get("9000", "viewer");
    expect(body.can).toEqual({ triage: false, assign: false, suppress: false, add_to_case: false, ask: false, export: false });
    expect((await get("9000", "rule_author")).status).toBe(403);
  });
});
