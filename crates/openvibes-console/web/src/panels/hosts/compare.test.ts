import { describe, expect, it } from "vitest";

import { diff, filterRows, pickable, rows } from "./compare";

describe("compare hosts (#120)", () => {
  it("lists what only one side has and what differs", () => {
    const a = new Map([["443/tcp", "exposed"], ["22/tcp", "exposed"], ["openssl.x86_64", "3.2.4-3"]]);
    const b = new Map([["443/tcp", "exposed"], ["80/tcp", "exposed"], ["openssl.x86_64", "3.2.4-1"]]);
    expect(diff(a, b)).toEqual({ onlyA: ["22/tcp"], onlyB: ["80/tcp"], changed: ["openssl.x86_64"] });
    expect(diff(a, a)).toEqual({ onlyA: [], onlyB: [], changed: [] });
  });

  it("flattens to typed rows and filters them", () => {
    const a = new Map([["22/tcp", "x"], ["openssl.x86_64", "1"]]);
    const b = new Map([["80/tcp", "x"], ["openssl.x86_64", "2"]]);
    const all = rows(a, b);
    expect(all).toEqual([{ key: "22/tcp", kind: "onlyA" }, { key: "80/tcp", kind: "onlyB" }, { key: "openssl.x86_64", kind: "changed" }]);
    expect(filterRows(all, "", "onlyB")).toEqual([{ key: "80/tcp", kind: "onlyB" }]);
    expect(filterRows(all, " SSL ", undefined)).toEqual([{ key: "openssl.x86_64", kind: "changed" }]);
    expect(filterRows(all, "", undefined)).toHaveLength(3);
  });

  it("offers other, non-revoked hosts by name, filtered by text", () => {
    const h = (id: string, hostname: string | null, status = "active", os_id = "fedora") => ({ id, hostname, status, os_id, os_version: "44" });
    const all = [h("1", "web-10"), h("2", "web-2"), h("3", "db-1", "revoked"), h("4", null, "active", "debian"), h("5", "me")];
    expect(pickable(all, "5", "").map((x) => x.id)).toEqual(["4", "2", "1"]);
    expect(pickable(all, "5", "DEBIAN").map((x) => x.id)).toEqual(["4"]);
    expect(pickable(all, "5", "web").map((x) => x.id)).toEqual(["2", "1"]);
  });
});
