// fitsShare: the client copy of the server's share rule (access/share.rs).
import { describe, expect, it } from "vitest";

import type { Capability, Permission, Role } from "../../../api/types";
import { fitsShare } from "./people";

const global = (permission: Permission): Capability => ({ permission, scope: { kind: "global" } });
const on = (permission: Permission, ...asset_group_ids: string[]): Capability => ({ permission, scope: { kind: "asset_groups", asset_group_ids } });
const g = (id: string) => ({ asset_group_id: id, name: id });
const role = (permissions: Permission[], reach: Role["reach"]): Role => ({ role_id: "r", name: "r", description: "", builtin: false, members: 0, version: 1, permissions, reach });

describe("fitsShare", () => {
  const cases: [string, Capability[], Role, boolean][] = [
    ["a permission the viewer lacks", [global("alarms.read")], role(["alarms.read", "hosts.read"], { kind: "all" }), false],
    ["a platform permission held only on groups", [on("rules.read", "g1")], role(["rules.read"], { kind: "all" }), true],
    ["a host permission held everywhere, role on all hosts", [global("hosts.read")], role(["hosts.read"], { kind: "all" }), true],
    ["a host permission held on groups, role on all hosts", [on("hosts.read", "g1")], role(["hosts.read"], { kind: "all" }), false],
    ["role on a subset of the viewer's groups", [on("hosts.read", "g1", "g2")], role(["hosts.read"], { kind: "groups", groups: [g("g1")] }), true],
    ["role on a group the viewer does not reach", [on("hosts.read", "g1")], role(["hosts.read"], { kind: "groups", groups: [g("g1"), g("g3")] }), false],
    ["role reaching no hosts", [on("hosts.read", "g1")], role(["hosts.read"], { kind: "none" }), true],
  ];
  it.each(cases)("%s", (_, caps, r, fits) => expect(fitsShare(caps, r)).toBe(fits));
});
