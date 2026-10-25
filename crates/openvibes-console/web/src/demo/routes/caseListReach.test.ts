// The Cases list's group counts take their reach from cases.read, as the
// store does (case_list_sql.rs `$1/$2`), not from hosts.read: Lee also holds
// Operator on Production, which reads its hosts but not its cases.
import { describe, expect, it, vi } from "vitest";

vi.mock("../data", async (original) => {
  const real = await original<typeof import("../data")>();
  return {
    ...real,
    buildDemoData: (now?: number) => {
      const data = real.buildDemoData(now);
      data.access.bindings.push({ user_id: "u-lee", role_id: "role-opprod" });
      return data;
    },
  };
});

type Body = { counts: { group: { value: string }[] } };
// test-setup.ts loaded the demo before this mock: load it again.
vi.resetModules();
const { createDemoServer } = await import("../server");
const groups = async (query: string) => {
  const response = await createDemoServer({ persona: "team_lead" }).handle("GET", `/api/v1/case-list?${query}`, undefined);
  return ((await response.json()) as Body).counts.group.map((g) => g.value);
};

describe("the Cases list's groups", () => {
  it("offer only groups the cases.read reach covers, even when chosen", async () => {
    expect(await groups("status=all")).not.toContain("grp-prod");
    expect(await groups("status=all&group=grp-prod")).not.toContain("grp-prod");
    expect(await groups("status=all&group=grp-pilot")).toContain("grp-pilot");
  });
});
