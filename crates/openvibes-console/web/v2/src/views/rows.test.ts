import { describe, expect, it } from "vitest";

import { selectAgents, selectAudit, selectFindings } from "./rows";

const group = (rule: string, severity: "critical" | "low", open: number) => ({
  rule_set_id: "s", rule_id: rule, severity, latest_message: `msg ${rule}`, endpoint_count: open + 1, older_endpoint_count: 0,
  rule_versions: [1], first_observed_at: "2026-09-01T00:00:00Z", last_observed_at: "2026-09-02T00:00:00Z",
  triage_counts: { open, investigating: 0, mitigated: 1, accepted_risk: 0, false_positive: 0 },
});

describe("list selection matches the views", () => {
  it("findings: open only by default, severity and text filters", () => {
    const all = [group("A", "critical", 2), group("B", "low", 0)];
    expect(selectFindings(all, new URLSearchParams()).map((g) => g.rule_id)).toEqual(["A"]);
    expect(selectFindings(all, new URLSearchParams("state=all")).map((g) => g.rule_id)).toEqual(["A", "B"]);
    expect(selectFindings(all, new URLSearchParams("state=all&severity=low")).map((g) => g.rule_id)).toEqual(["B"]);
    expect(selectFindings(all, new URLSearchParams("state=all&q=msg%20b")).map((g) => g.rule_id)).toEqual(["B"]);
  });

  it("agents: status and text", () => {
    const agent = (id: string, status: "active" | "stale") => ({ id, hostname: `${id}.example.test`, status, enrolled_at: "", capabilities: [] });
    const all = [agent("web", "active"), agent("db", "stale")];
    expect(selectAgents(all, new URLSearchParams("status=stale")).map((a) => a.id)).toEqual(["db"]);
    expect(selectAgents(all, new URLSearchParams("q=web")).map((a) => a.id)).toEqual(["web"]);
  });

  it("audit: failures filter", () => {
    const event = (id: string, result: string) => ({ id, action: "user.login", actor: "a", at: "2026-09-01T00:00:00Z", result });
    expect(selectAudit([event("1", "success"), event("2", "failure")], new URLSearchParams("result=failure")).map((e) => e.id)).toEqual(["2"]);
  });
});
