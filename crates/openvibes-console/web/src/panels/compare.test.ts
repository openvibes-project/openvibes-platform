import { describe, expect, it } from "vitest";

import { diff } from "./compare";

describe("compare hosts (#120)", () => {
  it("lists what only one side has and what differs", () => {
    const a = new Map([["443/tcp", "exposed"], ["22/tcp", "exposed"], ["openssl.x86_64", "3.2.4-3"]]);
    const b = new Map([["443/tcp", "exposed"], ["80/tcp", "exposed"], ["openssl.x86_64", "3.2.4-1"]]);
    expect(diff(a, b)).toEqual({ onlyA: ["22/tcp"], onlyB: ["80/tcp"], changed: ["openssl.x86_64"] });
    expect(diff(a, a)).toEqual({ onlyA: [], onlyB: [], changed: [] });
  });
});
