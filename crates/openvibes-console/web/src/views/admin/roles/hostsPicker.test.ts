import { describe, expect, it } from "vitest";

import { groupMeta } from "./HostsPicker";

describe("the host picker's group line", () => {
  it("names the kind and counts hosts", () => {
    expect(groupMeta({ kind: "rule", hosts: 12 })).toBe("Rule · 12 hosts");
    expect(groupMeta({ kind: "manual", hosts: 1 })).toBe("Manual · 1 host");
    expect(groupMeta({ kind: "automatic", hosts: 0 })).toBe("Automatic · 0 hosts");
  });
});
