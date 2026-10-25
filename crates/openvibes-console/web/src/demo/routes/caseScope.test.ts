// Who sees a case in the demo follows cases.read, not hosts.read (the
// server's case_visible over the cases.read scope). Pia holds hosts.read on
// Production and, here, cases.read on the pilot hosts only.
import { describe, expect, it, vi } from "vitest";

import type { CaseDetail } from "../../api/types";
import { inGroup } from "../hostGroups";

vi.mock("../data", async (importOriginal) => {
  const real = await importOriginal<typeof import("../data")>();
  return {
    ...real,
    buildDemoData: (now?: number) => {
      const data = real.buildDemoData(now);
      data.access.roles.push({ role_id: "role-pilotcases", name: "Pilot cases", description: "", builtin: false, permissions: ["cases.read"],
        reach: { kind: "groups", asset_group_ids: ["grp-pilot"] }, version: 1 });
      data.access.bindings.push({ user_id: "u-pia", role_id: "role-pilotcases" });
      return data;
    },
  };
});

describe("demo case visibility", () => {
  it("is the cases.read reach", async () => {
    // The test setup already loaded the demo; load it again through the mock.
    vi.resetModules();
    const { createDemoServer } = await import("../server");
    const now = Date.parse("2026-10-25T12:00:00Z");
    const admin = createDemoServer({ now });
    const pia = createDemoServer({ persona: "scoped_operator", now });
    const isIn = (agentId: string, id: string) => {
      const a = admin.data.agents.find((x) => x.id === agentId);
      const g = admin.data.access.host_groups.find((x) => x.asset_group_id === id);
      return !!a && !!g && inGroup({ ...a, last_address: admin.data.addresses.get(a.id) ?? null }, g);
    };
    const titles = async (s: typeof admin) =>
      ((await (await s.handle("GET", "/api/v1/cases?status=all&limit=100")).json()) as { items: { case_id: string; title: string }[] }).items;
    // Each demo seeds its own case ids: compare by title.
    const seen = new Set((await titles(pia)).map((c) => c.title));
    let differs = false;
    for (const { case_id, title } of await titles(admin)) {
      const detail = (await (await admin.handle("GET", `/api/v1/cases/${case_id}`)).json()) as CaseDetail;
      const hosts = detail.items.flatMap((i) => (i.agent_id == null ? [] : [i.agent_id]));
      const pilot = hosts.some((h) => isIn(h, "grp-pilot"));
      if (pilot !== hosts.some((h) => isIn(h, "grp-prod"))) differs = true;
      expect(seen.has(title), title).toBe(pilot);
    }
    expect(differs, "the seed has a case seen through one group and not the other").toBe(true);
  });
});
