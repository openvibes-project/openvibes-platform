// Enrollment token state, shared by the list and the panel.

import type { EnrollmentToken } from "../api/types";

export function tokenState(token: EnrollmentToken, now = Date.now()): { label: string; tone: string } {
  if (token.revoked) return { label: "Revoked", tone: "bad" };
  if (token.standing) return { label: "Standing", tone: "ok" };
  if (Date.parse(token.expires_at) <= now) return { label: "Expired", tone: "plain" };
  if (token.uses >= token.max_uses) return { label: "Used up", tone: "plain" };
  return { label: "Usable", tone: "ok" };
}

/** Whether new hosts can still enroll with the token. */
export function tokenUsable(token: EnrollmentToken, now = Date.now()): boolean {
  const label = tokenState(token, now).label;
  return label === "Usable" || label === "Standing";
}
