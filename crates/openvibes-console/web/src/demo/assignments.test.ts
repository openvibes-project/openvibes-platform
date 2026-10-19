import { describe, expect, it } from "vitest";

import type { HostRuleSetAssignments, RuleSetAssignments } from "../api/types";
import { createDemoServer } from "./server";

const get = async <T,>(server: ReturnType<typeof createDemoServer>, path: string) => (await (await server.handle("GET", path)).json()) as T;

describe("demo rule-set assignment", () => {
  it("starts with L1 on but off for Production, and L2 off and not published", async () => {
    const view = await get<RuleSetAssignments>(createDemoServer({ persona: "admin" }), "/api/v1/rule-set-assignments");
    const [l1, l2] = view.items;
    expect(l1).toMatchObject({ rule_set_id: "hardening-linux-l1", default_enabled: true, published: true, groups: [{ asset_group_id: "grp-prod", name: "Production", enabled: false }] });
    expect(l2).toMatchObject({ rule_set_id: "hardening-linux-l2", default_enabled: false, published: false, groups: [] });
    const prod = view.asset_groups.find((g) => g.name === "Production");
    expect(prod?.selectors).toEqual(["env=prod"]);
    expect(l1?.hosts_off).toBe(prod?.hosts);
    expect((l1?.hosts_on ?? 0) + (l1?.hosts_off ?? 0)).toBe(l2?.hosts_off);
  });

  it("a group switched on shows in the host view with its group; facts and pending come from the hosts", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await server.handle("PUT", "/api/v1/rule-set-assignments/hardening-linux-l2/groups/grp-lab", { enabled: true })).status).toBe(200);
    const lab = await get<HostRuleSetAssignments>(server, "/api/v1/agents/agent-00004/rule-set-assignments");
    expect(lab.items).toEqual([
      { rule_set_id: "hardening-linux-l1", enabled: true, source: "default", group: null, published: true },
      { rule_set_id: "hardening-linux-l2", enabled: true, source: "group", group: "Lab", published: false },
    ]);
    expect(lab.hardening_facts).toBe("ok");
    const prod = await get<HostRuleSetAssignments>(server, "/api/v1/agents/agent-00003/rule-set-assignments");
    expect(prod.items[0]).toEqual({ rule_set_id: "hardening-linux-l1", enabled: false, source: "group", group: "Production", published: true });
    const stale = await get<HostRuleSetAssignments>(server, "/api/v1/agents/agent-00017/rule-set-assignments");
    expect(stale.hardening_facts).toBe("not_found");
    expect(Date.now() - Date.parse(stale.hardening_facts_ok_at ?? "")).toBeGreaterThan(3 * 86_400_000 - 60_000);
    const never = await get<HostRuleSetAssignments>(server, "/api/v1/agents/agent-00034/rule-set-assignments");
    expect([never.hardening_facts, never.hardening_facts_ok_at]).toEqual(["not_found", null]);
    expect((await server.handle("DELETE", "/api/v1/rule-set-assignments/hardening-linux-l2/groups/grp-lab")).status).toBe(200);
    expect((await get<RuleSetAssignments>(server, "/api/v1/rule-set-assignments")).items[1]?.groups).toEqual([]);
  });

  it("an unknown group answers 404, a set that is not assignable 404, a bad body 400", async () => {
    const server = createDemoServer({ persona: "admin" });
    const unknown = await server.handle("PUT", "/api/v1/rule-set-assignments/hardening-linux-l1/groups/grp-gone", { enabled: true });
    expect([unknown.status, ((await unknown.json()) as { code: string }).code]).toEqual([404, "asset_group_not_found"]);
    expect((await server.handle("PUT", "/api/v1/rule-set-assignments/baseline", { default_enabled: false })).status).toBe(404);
    expect((await server.handle("PUT", "/api/v1/rule-set-assignments/hardening-linux-l1", { default_enabled: "no" })).status).toBe(400);
  });

  it("an analyst reads the rule list but not the switches, an operator reads both and changes switches, a viewer cannot change them", async () => {
    expect((await createDemoServer({ persona: "analyst" }).handle("GET", "/api/v1/rule-set-assignments")).status).toBe(403);
    const operator = createDemoServer({ persona: "operator" });
    expect((await operator.handle("GET", "/api/v1/rule-set-assignments")).status).toBe(200);
    expect((await operator.handle("PUT", "/api/v1/rule-set-assignments/hardening-linux-l1", { default_enabled: false })).status).toBe(200);
    for (const path of ["/api/v1/rule-sets", "/api/v1/rule-sets/hardening-linux-l1/bundles", "/api/v1/rules/coverage"]) {
      expect((await operator.handle("GET", path)).status, path).toBe(200);
      // The Analyst template holds rules.read and rules.coverage.read.
      expect((await createDemoServer({ persona: "analyst" }).handle("GET", path)).status, path).toBe(200);
    }
    expect((await createDemoServer({ persona: "viewer" }).handle("PUT", "/api/v1/rule-set-assignments/hardening-linux-l1", { default_enabled: false })).status).toBe(403);
  });

  it("with several groups on a host, on wins and the first on group by name decides", async () => {
    const server = createDemoServer({ persona: "admin" });
    const add = async (name: string) => {
      await new Promise((r) => setTimeout(r, 3)); // group ids come from the clock
      return ((await (await server.handle("POST", "/api/v1/access-control/asset-groups", { name, selectors: [{ key: "env", value: "prod" }] })).json()) as { asset_group_id: string }).asset_group_id;
    };
    const zeta = await add("Zeta");
    const alpha = await add("Alpha");
    const l1 = "/api/v1/rule-set-assignments/hardening-linux-l1/groups/";
    const host = async () => (await get<HostRuleSetAssignments>(server, "/api/v1/agents/agent-00003/rule-set-assignments")).items[0];
    await server.handle("PUT", l1 + zeta, { enabled: false });
    expect(await host()).toMatchObject({ enabled: false, source: "group", group: "Production" });
    await server.handle("PUT", l1 + zeta, { enabled: true });
    expect(await host()).toMatchObject({ enabled: true, group: "Zeta" });
    const before = (await get<RuleSetAssignments>(server, "/api/v1/rule-set-assignments")).items[0]?.hosts_on ?? 0;
    expect(before).toBeGreaterThan(0);
    await server.handle("PUT", l1 + alpha, { enabled: true });
    expect(await host()).toMatchObject({ enabled: true, group: "Alpha" });
  });
});
