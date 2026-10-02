import { describe, expect, it } from "vitest";

import { menuCount } from "../app/menuCount";

describe("menu counts (#117)", () => {
  it("shows nothing at zero, the number up to 99, then 99+", () => {
    expect(menuCount(0)).toBeUndefined();
    expect(menuCount(undefined)).toBeUndefined();
    expect(menuCount(1)).toBe("1");
    expect(menuCount(99)).toBe("99");
    expect(menuCount(100)).toBe("99+");
    expect(menuCount(40, true)).toBe("99+");
  });
});
