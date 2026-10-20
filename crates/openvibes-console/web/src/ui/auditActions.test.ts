import { describe, expect, it } from "vitest";

import { auditActionLabel } from "./auditActions";

describe("audit action labels", () => {
  it("names the actions the platform writes", () => {
    expect(auditActionLabel("auth.login.succeeded")).toBe("Signed in");
    expect(auditActionLabel("rbac.binding.created")).toBe("Gave a role");
    expect(auditActionLabel("settings.changed")).toBe("Changed a setting");
    expect(auditActionLabel("rbac.role.created")).toBe("Created a role");
    expect(auditActionLabel("alarm.suppression.created")).toBe("Suppressed alarms");
    expect(auditActionLabel("alarm.suppression.requested")).toBe("Requested a suppression");
    expect(auditActionLabel("alarm.suppression.approved")).toBe("Approved a suppression");
    expect(auditActionLabel("alarm.suppression.rejected")).toBe("Rejected a suppression");
    expect(auditActionLabel("alarm.suppression.withdrawn")).toBe("Withdrew a suppression request");
    expect(auditActionLabel("alarm.suppression.removed")).toBe("Removed a suppression");
    expect(auditActionLabel("alarm.triage.changed")).toBe("Triaged an alarm");
  });
  it("reads an unknown id as words", () => {
    expect(auditActionLabel("rule_set.changed")).toBe("Rule set changed");
    expect(auditActionLabel("")).toBe("");
  });
});
