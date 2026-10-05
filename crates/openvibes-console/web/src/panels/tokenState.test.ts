import { describe, expect, it } from "vitest";
import type { EnrollmentToken } from "../api/types";
import { tokenState, tokenUsable } from "./tokens";

const now = Date.parse("2026-10-05T12:00:00Z");
const base: EnrollmentToken = { token_id: "t", label: null, created_at: "2026-10-01T00:00:00Z", expires_at: "2026-10-10T00:00:00Z", max_uses: 2, uses: 0, revoked: false, standing: false };

describe("enrollment token state", () => {
  it("tells usable, used-up, expired and revoked tokens apart", () => {
    expect(tokenState(base, now).label).toBe("Usable");
    expect(tokenState({ ...base, uses: 2 }, now).label).toBe("Used up");
    expect(tokenState({ ...base, expires_at: "2026-10-02T00:00:00Z" }, now).label).toBe("Expired");
    expect(tokenState({ ...base, revoked: true }, now).label).toBe("Revoked");
  });

  it("treats the standing token as usable whatever its placeholder expiry and limit say", () => {
    const standing = { ...base, standing: true, expires_at: "2020-01-01T00:00:00Z", max_uses: 1, uses: 50 };
    expect(tokenState(standing, now).label).toBe("Standing");
    expect(tokenUsable(standing, now)).toBe(true);
    expect(tokenUsable({ ...standing, revoked: true }, now)).toBe(false);
    expect(tokenUsable({ ...base, uses: 2 }, now)).toBe(false);
  });
});
