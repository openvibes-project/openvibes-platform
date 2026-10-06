import { describe, expect, it } from "vitest";

import { diff, filterRows, rows } from "./compare";

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
});
