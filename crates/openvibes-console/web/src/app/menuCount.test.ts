import { describe, expect, it } from "vitest";

import { menuCount, waitingToDecide } from "./menuCount";

describe("menu counts (#117)", () => {
  it("shows nothing at zero, the number up to 99, then 99+", () => {
    expect(menuCount(0)).toBeUndefined();
    expect(menuCount(undefined)).toBeUndefined();
    expect(menuCount(1)).toBe("1");
    expect(menuCount(99)).toBe("99");
    expect(menuCount(100)).toBe("99+");
    expect(menuCount(40, true)).toBe("99+");
  });
  it("counts the waiting suppressions the viewer can decide", () => {
    const row = (status: string, can_decide: boolean) => ({ status, can_decide });
    expect(waitingToDecide([row("waiting", true), row("waiting", true), row("waiting", false), row("active", true)])).toBe("2");
    expect(waitingToDecide([row("waiting", false)])).toBeUndefined();
    expect(waitingToDecide(undefined)).toBeUndefined();
  });
});
