import { describe, expect, it } from "vitest";
import type { Session } from "../api/types";
import { holdsEverywhere } from "./session";

const session = (scope: object) => ({ capabilities: [{ permission: "alarms.suppress", scope }] }) as unknown as Session;

describe("holdsEverywhere", () => {
  it("a group-limited alarms.suppress holder may only quiet one host", () => {
    expect(holdsEverywhere(session({ kind: "asset_groups", asset_group_ids: ["g"] }), "alarms.suppress")).toBe(false);
  });
  it("an unscoped holder may quiet every host", () => {
    expect(holdsEverywhere(session({ kind: "global" }), "alarms.suppress")).toBe(true);
  });
});
