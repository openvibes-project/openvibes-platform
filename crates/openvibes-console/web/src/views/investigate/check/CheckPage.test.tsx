// A check's page (approved screen 28), as markup: no DOM library in vitest
// (see ui/controls.test.tsx); the actions are covered by e2e/demo/check-page.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { CheckHostsPage, CheckSummaryPage, Session } from "../../../api/types";
import { SessionContext } from "../../../app/session";
import { HostsTable, evidenceText, hostItems, segmentOf, stateOf, stateOptions } from "./CheckCards";
import { CheckView, exportRows, headerItems } from "./CheckPage";

type Row = CheckHostsPage["rows"][number];
const ALL = { triage: true, assign: true, add_to_case: true, ask: true, export: true };
const ROOT = "harden.ssh.permit_root_login";
const fixture = (over: Partial<CheckSummaryPage> = {}): CheckSummaryPage => ({
  header: {
    title: "SSH allows root login", severity: "critical", rule_set_id: "hardening-linux-l1", rule_set_version: 4, rule_id: ROOT, rule_version: 3,
    area: "SSH", failing: 2, open: 2, checked: 5, assignee: { kind: "one", id: "u-sam", name: "Sam Analyst" },
  },
  tiles: { failing: 2, passing: 3, first_seen: { at: "2026-07-23T10:00:00Z", hostname: "web-01" }, days: [3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2] },
  text: { explain: "One stolen password gives full control.", check: "Set PermitRootLogin no, then systemctl reload sshd.", message: "Root may log in over SSH" },
  details: { applies_to: "Linux hosts", techniques: ["T1078", "T1110"] },
  history: [
    { kind: "triage", at: "2026-10-22T10:00:00Z", actor: "Sam Analyst", agent_id: "agent-1", hostname: "web-01", from_state: "open", to_state: "mitigated", note: "firewalled", version: null },
    { kind: "passes_again", at: "2026-10-18T10:00:00Z", actor: null, agent_id: "agent-2", hostname: "db-02", from_state: null, to_state: null, note: null, version: null },
    { kind: "failing", at: "2026-10-17T10:00:00Z", actor: null, agent_id: "agent-3", hostname: "mx-01", from_state: null, to_state: null, note: null, version: null },
    { kind: "published", at: "2026-10-01T10:00:00Z", actor: "admin", agent_id: null, hostname: null, from_state: null, to_state: null, note: null, version: 4 },
  ],
  related: { port: { port: 22, protocol: "tcp", hosts: 4 }, service: { unit: "sshd.service", hosts: 3 }, same_area: { checks: 1, worst: "high" } },
  can: ALL,
  ...over,
});
const session = { principal: { id: "u-me", username: "me", display_name: "Me" }, capabilities: [] } as unknown as Session;
const render = (node: React.ReactNode, can = true) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session, demo: false, can: () => can, canEverywhere: () => can }}>{node}</SessionContext.Provider>,
).replace(/<!-- -->/g, "");
const text = (html: string) => html.replace(/<[^>]+>/g, "");

describe("check page", () => {
  it("names the check, its rule set, area, reach and assignee in the header", () => {
    const t = text(render(<CheckView page={fixture()} />));
    expect(t).toContain("SSH allows root login");
    expect(t).toContain("Critical");
    expect(t).toContain(`${ROOT} · hardening-linux-l1 v4 · SSH · failing on 2 of 5 hosts checked · assigned to Sam Analyst`);
  });

  it("has the four tiles; failing on leads to the Hosts card; the bars say where the 14 days went", () => {
    const html = render(<CheckView page={fixture()} />);
    expect(html).toMatch(/<a [^>]*href="#hosts"[^>]*aria-label="Failing on, of 5 hosts checked: 2"/);
    expect(html).toContain('id="hosts"');
    const t = text(html);
    expect(t).toContain("3Passing");
    expect(t).toMatch(/First seen on web-01/);
    expect(t).toContain("Last 14 days");
    expect(t).toContain("3 → 2 hosts failing");
    expect(html.match(/<rect/g)).toHaveLength(14);
    expect(t).toContain("today");
    expect(text(render(<CheckView page={fixture({ tiles: { ...fixture().tiles, first_seen: null } })} />))).toContain("—First seen");
  });

  it("shows why it matters and how to fix it, else the message and a link to the rule", () => {
    const t = text(render(<CheckView page={fixture()} />));
    expect(t).toContain("One stolen password gives full control.");
    expect(t).toContain("Set PermitRootLogin no, then systemctl reload sshd.");
    const bare = render(<CheckView page={fixture({ text: { explain: null, check: null, message: "Root may log in over SSH" } })} />);
    expect(text(bare)).toContain("Why it mattersRoot may log in over SSH");
    expect(text(bare)).toContain("No fix text yet");
    expect(bare).toContain('href="?open=rule-set%3Ahardening-linux-l1"');
  });

  it("names no rule set for a check from before rule sets, and links nowhere", () => {
    const html = render(<CheckView page={fixture({ header: { ...fixture().header, rule_set_id: "~unknown", rule_set_version: null },
      text: { explain: null, check: null, message: "m" } })} />);
    expect(html).not.toContain("rule-set%3A~unknown");
    const t = text(html);
    expect(t).toContain("Rule setNo rule set (from before rule sets)");
    expect(t).toContain("How to fixNo fix text yet.");
    expect(t).not.toContain("See the rule");
  });

  it("lists the details and the history, newest first", () => {
    const t = text(render(<CheckView page={fixture()} />));
    expect(t).toContain(`${ROOT} · version 3`);
    expect(t).toContain("hardening-linux-l1 v4");
    expect(t).toContain("Linux hosts");
    expect(t).toContain("T1078, T1110");
    expect(t).toContain("Sam Analyst set web-01 to Mitigated “firewalled”");
    expect(t).toContain("db-02 passes again");
    expect(t).toContain("mx-01 started failing");
    expect(t).toContain("Rule set hardening-linux-l1 v4 published by admin");
  });

  it("relates the port, the service and the same area's checks", () => {
    const html = render(<CheckView page={fixture()} />);
    const t = text(html);
    expect(t).toContain("22/tcp, exposed on 4 hosts");
    expect(t).toContain("sshd.service, on 3 hosts");
    expect(t).toContain("1 other failing check in SSH");
    expect(html).toContain('href="/compliance?area=SSH"');
    const none = text(render(<CheckView page={fixture({ related: { port: null, service: null, same_area: { checks: 0, worst: null } } })} />));
    expect(none).not.toContain("Port");
    expect(none).toContain("No other failing checks in SSH");
  });

  it("shows each action only with its can flag; Set state and Assign only with an open host", () => {
    const all = render(<CheckView page={fixture()} />);
    expect(all).toContain("Set state");
    expect(all).toContain("Ask about this");
    const none = render(<CheckView page={fixture({ can: { triage: false, assign: false, add_to_case: false, ask: false, export: false } })} />);
    expect(none).not.toContain("Set state");
    expect(none).not.toContain("Ask about this");
    expect(none).not.toContain("Add to case");
    expect(none).toContain('aria-label="More actions"');
    const closed = render(<CheckView page={fixture({ header: { ...fixture().header, open: 0 } })} />);
    expect(closed).not.toContain("Set state");
    expect(text(closed)).toContain("Add to case");
  });

  it("acts on the check's open failing hosts from the header", () => {
    expect(headerItems(fixture())).toEqual([{ rule_set_id: "hardening-linux-l1", rule_id: ROOT, open_only: true }]);
  });

  it("exports the hosts as CSV rows", () => {
    const rows = exportRows([row("agent-1", { evidence: [{ fact: "sshd.permitrootlogin", value: "yes", file: "/etc/ssh/sshd_config" }] })], fixture().header);
    expect(rows[0]).toEqual(["rule_set", "rule", "host", "agent_id", "os", "address", "state", "evidence", "assignee", "checked_at"]);
    expect(rows[1]).toEqual(["hardening-linux-l1", ROOT, "host-1", "agent-1", "Fedora 44", "10.0.0.1", "open", "sshd.permitrootlogin = yes (/etc/ssh/sshd_config)", "", "2026-10-22T10:00:00Z"]);
  });
});

const row = (agent: string, over: Partial<Row> = {}): Row => ({
  agent_id: agent, hostname: agent.replace("agent", "host"), os: "Fedora 44", address: "10.0.0.1", state: "open", evidence: [], assignee: null,
  checked_at: "2026-10-22T10:00:00Z", triage_version: 1, accepted_until: null, origin: "online", ...over,
});

const table = (rows: Row[], props: Partial<React.ComponentProps<typeof HostsTable>> = {}) =>
  render(<HostsTable rows={rows} selected={new Set()} onSelect={() => undefined} triage set="s" rule="r" {...props} />);
const passing = () => row("agent-2", { state: "passing", triage_version: null });

describe("hosts card", () => {
  it("ticks failing rows only; a passing row has no checkbox", () => {
    const html = table([row("agent-1"), passing()]);
    expect(html.match(/type="checkbox"/g)).toHaveLength(2); // the header's and agent-1's
    expect(html).toContain('aria-label="Select host-1"');
    expect(text(html)).toContain("Passing");
  });

  it("shows evidence as fact = value plus the file, and a masked value only as its status", () => {
    expect(evidenceText({ fact: "sshd.permitrootlogin", value: "yes", file: "/etc/ssh/sshd_config" })).toBe("sshd.permitrootlogin = yes (/etc/ssh/sshd_config)");
    expect(evidenceText({ fact: "user.password", status: "masked" })).toBe("user.password (masked)");
    const html = table([row("agent-1", { evidence: [{ fact: "sshd.permitrootlogin", value: "yes", file: "/etc/ssh/sshd_config" }, { fact: "k", status: "masked" }] })]);
    const t = text(html);
    expect(t).toContain("sshd.permitrootlogin = yes");
    expect(t).toContain("/etc/ssh/sshd_config");
    expect(t).toContain("k (masked)");
  });

  it("each failing row opens its evidence, the observation and why it triggered", () => {
    const html = table([row("agent-1"), passing()]);
    expect(html.match(/>View evidence</g)).toHaveLength(1);
    expect(html).toContain('aria-expanded="false"');
  });

  it("says until when a risk is accepted, and when an acceptance expired", () => {
    const t = text(table([row("agent-1", { state: "accepted_risk", accepted_until: "2099-01-01T00:00:00Z" }),
      row("agent-2", { state: "open", accepted_until: "2020-01-01T00:00:00Z" })]));
    expect(t).toMatch(/until /);
    expect(t).toMatch(/acceptance expired /);
  });

  it("shows each host's open cases", () => {
    const t = text(table([row("agent-1")], { cases: new Map([["agent-1", [104]]]) }));
    expect(t).toContain("C-104");
  });

  it("without triage but with cases, each failing row has its own Add to case", () => {
    const html = table([row("agent-1"), passing()], { triage: false, addToCase: true, title: "Root login" });
    expect(html).not.toContain('type="checkbox"');
    expect(html.match(/aria-label="Add Root login on host-\d to a case"/g)).toEqual(['aria-label="Add Root login on host-1 to a case"']);
  });

  it("sends ticked rows as host and check pairs, without open_only", () => {
    expect(hostItems([row("agent-1", { state: "mitigated" })], "s", "r")).toEqual([{ agent_id: "agent-1", rule_set_id: "s", rule_id: "r" }]);
  });

  it("marks an imported host, as the old panel did", () => {
    const t = text(table([row("agent-1", { origin: "import" }), row("agent-2", { origin: "online" })]));
    expect(t.match(/imported/g)).toHaveLength(1);
  });

  it("names each View evidence by its host", () => {
    const html = table([row("agent-1"), row("agent-2")]);
    expect(html).toContain('aria-label="View evidence on host-1"');
    expect(html).toContain('aria-label="View evidence on host-2"');
  });

  it("narrows the Failing segment by triage state, with counts; an unknown state is all failing", () => {
    expect(stateOf("mitigated")).toBe("mitigated");
    expect(stateOf("bogus")).toBeNull();
    expect(stateOf(null)).toBeNull();
    expect(stateOptions({ open: 2, mitigated: 1, accepted_risk: 1, false_positive: 0 }, 4)).toEqual([
      { key: "", label: "All failing", count: 4 }, { key: "open", label: "Open", count: 2 }, { key: "mitigated", label: "Mitigated", count: 1 },
      { key: "accepted_risk", label: "Accepted risk", count: 1 }, { key: "false_positive", label: "False positive", count: 0 },
    ]);
  });

  it("reads an unknown segment as all", () => {
    expect(segmentOf("failing")).toBe("failing");
    expect(segmentOf("bogus")).toBe("all");
    expect(segmentOf(null)).toBe("all");
  });
});
