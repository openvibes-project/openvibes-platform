// A port's page (approved screen 20), as markup: no DOM library in vitest
// (see ui/controls.test.tsx); the actions are covered by e2e/demo/port-page.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { PortPageHosts, PortPageSummary, Session } from "../../../api/types";
import { SessionContext } from "../../../app/session";
import { CHANGE_TEXT, HostsTable, segmentOf, stale } from "./PortCards";
import { PortView, exportRows } from "./PortPage";

const ALL = { export: true, add_to_case: true, ask: true };
const fixture = (over: Partial<PortPageSummary> = {}): PortPageSummary => ({
  header: { protocol: "tcp", port: 22, name: "SSH", usual_use: "Secure remote login", listening: 12, of: 14, exposed: 3, services: 1, first_seen: { at: "2026-08-01T00:00:00Z", before: true } },
  tiles: { listening: 12, exposed: 3, local: 9, week: { added: 2, removed: 1 } },
  details: { programs: ["sshd"], owners: { collected: 10, of: 12 } },
  by_group: [{ group_id: "g1", name: "Web", kind: "rule", listening: 8, of: 10 }],
  changes: [
    { at: "2026-10-26T10:00:00Z", agent_id: "agent-1", hostname: "web-01", change: "appeared" },
    { at: "2026-10-25T10:00:00Z", agent_id: "agent-2", hostname: "db-02", change: "local" },
  ],
  related: {
    compliance: { items: [{ rule_set_id: "baseline", rule_id: "ssh-root", title: "Root login over SSH is allowed", severity: "high", hosts: 2 }], total: 3, area: "SSH" },
    vulnerabilities: [{ package: "openssh", advisories: 2, hosts: 3 }],
    alarms: { program_not_collected: false, open: 0, hosts: 0 },
  },
  can: ALL,
  ...over,
});
const session = { principal: { id: "u-me", username: "me", display_name: "Me" }, capabilities: [] } as unknown as Session;
const render = (node: React.ReactNode, can = true) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session, demo: false, can: () => can, canEverywhere: () => can }}>{node}</SessionContext.Provider>,
).replace(/<!-- -->/g, "");
const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
/** The markup's text with tags dropped and nothing added, for a line that is one run ("a · b"). */
const flat = (html: string) => html.replace(/<[^>]+>/g, "");

describe("port page", () => {
  it("names the port and its facts in the header", () => {
    const t = flat(render(<PortView page={fixture()} />));
    expect(t).toContain("22/tcp SSH");
    expect(t).toContain("TCP");
    expect(t).toContain("Secure remote login · listening on 12 of 14 hosts · exposed on 3 · 1 service · before ");
  });

  it("shows the four tiles, linking Exposed and Local only to the Hosts segments", () => {
    const html = render(<PortView page={fixture()} />);
    expect(html).toContain('aria-label="Listening, of 14 hosts: 12"');
    expect(html).toContain('href="/ports/22/tcp?segment=exposed"');
    expect(html).toContain('href="/ports/22/tcp?segment=local"');
    expect(text(html)).toContain("+2 −1");
    expect(text(render(<PortView page={fixture({ tiles: { listening: 1, exposed: 0, local: 1, week: { added: 0, removed: 0 } } })} />))).toContain("No change");
  });

  it("says when owners are not collected", () => {
    expect(flat(render(<PortView page={fixture()} />))).toContain("sshd · not collected on 2 of 12 hosts");
    const none = text(render(<PortView page={fixture({ details: { programs: [], owners: { collected: 0, of: 12 } } })} />));
    expect(none).toContain("Programs Not collected on 12 hosts");
    expect(text(render(<PortView page={fixture({ details: { programs: ["sshd"], owners: { collected: 12, of: 12 } } })} />))).not.toContain("not collected on");
  });

  it("bars each group's share and says what changed, in the log's four words", () => {
    const html = render(<PortView page={fixture()} />);
    expect(html).toContain('href="/hosts?group=g1"');
    expect(text(html)).toContain("8 of 10");
    expect(text(html)).toContain("web-01 started listening");
    expect(text(html)).toContain("db-02 now listens only locally");
    expect(CHANGE_TEXT).toEqual({ appeared: "started listening", went_away: "stopped listening", local: "now listens only locally", exposed: "is now exposed" });
  });

  it("has Related sections only for what the person may read", () => {
    const t = text(render(<PortView page={fixture()} />));
    expect(t).toContain("Failing checks");
    expect(t).toContain("Root login over SSH is allowed");
    expect(t).toContain("2 more");
    expect(t).toContain("openssh");
    expect(t).toContain("2 open on 3 hosts");
    expect(t).toContain("None open");
    const bare = text(render(<PortView page={fixture({ related: {} })} />));
    expect(bare).not.toContain("Related");
    const some = text(render(<PortView page={fixture({ related: { alarms: { program_not_collected: true, open: 0, hosts: 0 } } })} />));
    expect(some).toContain("Program not collected");
    expect(some).not.toContain("Failing checks");
  });

  it("offers the actions the server allows", () => {
    const html = render(<PortView page={fixture()} />);
    expect(html).toContain("Ask about this");
    expect(html).toContain("Add to case");
    const none = render(<PortView page={fixture({ can: { export: false, add_to_case: false, ask: false } })} />);
    expect(none).not.toContain("Ask about this");
    expect(none).not.toContain("Add to case");
  });

  it("exports the hosts, one row each", () => {
    const rows = exportRows([{ agent_id: "agent-1", hostname: "web-01", os: "Debian 12", ip: "10.0.0.1", bound: ["0.0.0.0", "::"], exposed: true, service: "sshd.service", program: "sshd", owners_partial: false, reported_at: "2026-10-27T01:00:00Z" }], "tcp", 22);
    expect(rows[0]).toEqual(["port", "protocol", "host", "agent_id", "os", "address", "listening_on", "exposed", "service", "program", "last_report"]);
    expect(rows[1]).toEqual([22, "tcp", "web-01", "agent-1", "Debian 12", "10.0.0.1", "0.0.0.0 ::", "yes", "sshd.service", "sshd", "2026-10-27T01:00:00Z"]);
  });
});

describe("port hosts table", () => {
  const host = (over: Partial<PortPageHosts["items"][number]> = {}): PortPageHosts["items"][number] => ({
    agent_id: "agent-1", hostname: "web-01", os: "Debian 12", bound: ["0.0.0.0", "::"], exposed: true, owners_partial: false, reported_at: new Date().toISOString(), ...over,
  });

  it("shows 'not collected' for a missing owner on a partial host and a dash on a complete one", () => {
    const html = render(<HostsTable rows={[host({ agent_id: "a", hostname: "partial", owners_partial: true }), host({ agent_id: "b", hostname: "complete" })]} />);
    expect(text(html)).toContain("not collected");
    expect(html).toContain('title="Nothing owns it"');
  });

  it("lists every bound address, and exposure", () => {
    const html = render(<HostsTable rows={[host(), host({ agent_id: "b", hostname: "lin", bound: ["127.0.0.1"], exposed: false })]} />);
    expect(text(html)).toContain("0.0.0.0, ::");
    expect(text(html)).toContain("exposed");
    expect(text(html)).toContain("local only");
  });

  it("warns about a report more than a day old", () => {
    const now = Date.parse("2026-10-27T12:00:00Z");
    expect(stale("2026-10-26T11:59:00Z", now)).toBe(true);
    expect(stale("2026-10-26T12:01:00Z", now)).toBe(false);
    expect(stale(null, now)).toBe(false);
    expect(render(<HostsTable rows={[host({ reported_at: "2020-01-01T00:00:00Z" })]} />)).toContain("text-warn");
  });

  it("reads the segment from the URL, anything unknown being All", () => {
    expect([segmentOf("exposed"), segmentOf("local"), segmentOf("all"), segmentOf("x"), segmentOf(null)]).toEqual(["exposed", "local", "all", "all", "all"]);
  });
});
