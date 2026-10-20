// The demo's twin of platform-store's version_order (plan ruling 7): the
// same table as crates/platform-store/tests/version_order.rs.
import { describe, expect, it } from "vitest";

import { compareVersions, older } from "./versionOrder";

const TABLE: [string, string, boolean | null][] = [
  ["0.4.1", "0.4.2", true],
  ["0.4.2", "0.4.1", false],
  ["0.10.0", "0.9.9", false],
  ["0.9.9", "0.10.0", true],
  ["1.0.0-rc1", "1.0.0", true],
  ["1.0.0", "1.0.0-rc1", false],
  ["1.0.0+abc", "1.0.0", false],
  ["1.0.0", "1.0.0+abc", false],
  ["1.0", "1.0.0", false],
  ["1.0", "1.0.1", true],
  ["abc", "1.0.0", null],
  ["1.0.0", "abc", null],
  ["", "1.0.0", null],
  ["1.0.0", "", null],
  ["1..0", "1.0.0", null],
  ["99999999999", "1.0.0", null],
];

describe("versionOrder", () => {
  it.each(TABLE)("%s older than %s: %s", (version, latest, want) => {
    expect(older(version, latest)).toBe(want);
  });

  it("sorts numerically, a pre-release before its release, unknown last both ways", () => {
    const sorted = ["0.10.0", "x", "0.9.9", "0.10.0-rc.1", "0.4.2"].sort((a, b) => compareVersions(a, b));
    expect(sorted).toEqual(["0.4.2", "0.9.9", "0.10.0-rc.1", "0.10.0", "x"]);
    const down = ["0.10.0", "x", "0.9.9", "0.10.0-rc.1", "0.4.2"].sort((a, b) => compareVersions(a, b, -1));
    expect(down).toEqual(["0.10.0", "0.10.0-rc.1", "0.9.9", "0.4.2", "x"]);
    // As SQL compares int[]: trailing zero segments dropped, then the shorter first.
    expect(compareVersions("1.0", "1.0.0")).toBe(0);
    expect(compareVersions("1.2", "1.2.1")).toBeLessThan(0);
  });
});
