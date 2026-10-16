import { describe, expect, it } from "vitest";

import { auditActionLabel } from "./auditActions";

describe("audit action labels", () => {
  it("names the actions the platform writes", () => {
    expect(auditActionLabel("auth.login.succeeded")).toBe("Signed in");
    expect(auditActionLabel("rbac.binding.created")).toBe("Gave a role");
    expect(auditActionLabel("rbac.role.created")).toBe("Created a role");
    expect(auditActionLabel("alarm.suppression.created")).toBe("Suppressed alarms");
    expect(auditActionLabel("alarm.triage.changed")).toBe("Triaged an alarm");
  });
  it("reads an unknown id as words", () => {
    expect(auditActionLabel("rule_set.changed")).toBe("Rule set changed");
    expect(auditActionLabel("")).toBe("");
  });
});
