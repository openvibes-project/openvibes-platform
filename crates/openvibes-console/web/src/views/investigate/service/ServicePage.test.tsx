// A service's page (approved screen 22), as markup: no DOM library in vitest
// (see ui/controls.test.tsx); the actions are covered by e2e/demo/service-page.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { ServicePageHosts, ServicePageSummary, Session } from "../../../api/types";
import { SessionContext } from "../../../app/session";
import { CHANGE_TEXT, HostsTable, isRoot, segmentOf, stale } from "./ServiceCards";
import { ServiceView, exportRows } from "./ServicePage";

const ALL = { export: true, add_to_case: true };
const fixture = (over: Partial<ServicePageSummary> = {}): ServicePageSummary => ({
  header: { unit: "sshd.service", name: "OpenSSH server", usual_use: "Secure remote login", running: 12, of: 14, exposed: 3, root: 12, first_seen: { at: "2026-08-01T00:00:00Z", before: true } },
  tiles: { running: 12, alarms: 1, vulnerabilities: 2, versions: 2 },
  details: {
    run_as: [{ user: "root", hosts: 12 }], programs: ["sshd"], packages: [{ name: "openssh-server", hosts: 10 }], package_hosts: 10, processes: 14, week: { added: 2, removed: 1 },
  },
  ports: [{ protocol: "tcp", port: 22, exposed: true, hosts: 12 }, { protocol: "tcp", port: 2222, exposed: false, hosts: 1 }],
  by_group: [{ group_id: "g1", name: "Web", kind: "rule", running: 8, of: 10 }],
  changes: [
    { at: "2026-10-26T10:00:00Z", agent_id: "agent-1", hostname: "web-01", change: "appeared" },
    { at: "2026-10-25T10:00:00Z", agent_id: "agent-2", hostname: "db-02", change: "went_away" },
  ],
  related: {
    compliance: { items: [{ rule_set_id: "baseline", rule_id: "ssh-root", title: "Root login over SSH is allowed", severity: "high", hosts: 2 }], total: 3, area: "SSH" },
    vulnerabilities: { advisories: 2, hosts: 3, packages: [{ package: "openssh-server", advisories: 2, hosts: 3 }] },
    alarms: { programs_not_collected: false, open: 0, hosts: 0 },
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

describe("service page", () => {
  it("names the unit and its facts in the header", () => {
    const t = flat(render(<ServiceView page={fixture()} />));
    expect(t).toContain("sshd.service OpenSSH server");
    expect(t).toContain("Secure remote login · running on 12 of 14 hosts · as root on 12 · owns an exposed port on 3 · this week +2 −1 · before ");
    expect(flat(render(<ServiceView page={fixture({ header: { unit: "x.service", running: 1, of: 2, exposed: 0, root: 0 } })} />))).toContain("Not a usual service · running on 1 of 2 hosts");
  });

  it("shows the four tiles, the first linking to the Hosts card", () => {
    const html = render(<ServiceView page={fixture()} />);
    expect(html).toContain('aria-label="Running on, of 14 hosts: 12"');
    expect(html).toContain('href="#hosts"');
    const t = text(html);
    expect(t).toContain("Open alarms from its programs");
    expect(t).toContain("Vulnerabilities in its package");
    expect(t).toContain("Versions in use");
  });

  it("leaves out the tiles the person may not read, and dashes versions when no package matched", () => {
    const t = text(render(<ServiceView page={fixture({ tiles: { running: 12 } })} />));
    expect(t).not.toContain("Open alarms from its programs 1");
    expect(t).not.toContain("Vulnerabilities in its package");
    expect(t).toContain("— Versions in use");
  });

  it("says the package is matched by name, and where it is missing", () => {
    const t = text(render(<ServiceView page={fixture()} />));
    expect(t).toContain("openssh-server on 10 hosts");
    expect(t).toContain("matched by name");
    expect(t).toContain("not on 2 hosts");
    expect(text(render(<ServiceView page={fixture({ details: { run_as: [], programs: [], packages: [], package_hosts: 0, processes: 0, week: { added: 0, removed: 0 } } })} />))).toContain("Not from a package");
  });

  it("links each owned port to its page, exposed ones in amber", () => {
    const html = render(<ServiceView page={fixture()} />);
    expect(html).toContain('href="/ports/22/tcp"');
    expect(html).toContain('href="/ports/2222/tcp"');
    expect(text(html)).toContain("exposed");
    expect(text(html)).toContain("local only");
  });

  it("bars each group's share and says what changed, in the log's two words", () => {
    const html = render(<ServiceView page={fixture()} />);
    expect(html).toContain('href="/hosts?group=g1"');
    expect(text(html)).toContain("8 of 10");
    expect(text(html)).toContain("web-01 started running it");
    expect(text(html)).toContain("db-02 stopped running it");
    expect(CHANGE_TEXT).toEqual({ appeared: "started running it", went_away: "stopped running it" });
  });

  it("has Related sections only for what the person may read", () => {
    const t = text(render(<ServiceView page={fixture()} />));
    expect(t).toContain("Failing checks");
    expect(t).toContain("Root login over SSH is allowed");
    expect(t).toContain("2 more");
    expect(t).toContain("openssh-server");
    expect(t).toContain("2 open on 3 hosts");
    expect(t).toContain("None open");
    const bare = text(render(<ServiceView page={fixture({ related: {} })} />));
    expect(bare).not.toContain("Related");
    const some = text(render(<ServiceView page={fixture({ related: { alarms: { programs_not_collected: true, open: 0, hosts: 0 } } })} />));
    expect(some).toContain("Programs not collected");
    expect(some).not.toContain("Failing checks");
  });

  it("offers Add to case only when the server allows, and has no Ask button", () => {
    const html = render(<ServiceView page={fixture()} />);
    expect(html).toContain("Add to case");
    expect(html).not.toContain("Ask about this");
    expect(render(<ServiceView page={fixture({ can: { export: false, add_to_case: false } })} />)).not.toContain("Add to case");
  });

  it("exports the hosts, one row each", () => {
    const rows = exportRows([{
      agent_id: "agent-1", hostname: "web-01", os: "Debian 12", ip: "10.0.0.1", processes: 3, programs: ["sshd"], run_as: "root", package: { name: "openssh-server", version: "9.2-1" },
      ports: [{ protocol: "tcp", port: 22, exposed: true }], owners_partial: false, problems: {}, reported_at: "2026-10-27T01:00:00Z",
    }], "sshd.service");
    expect(rows[0]).toEqual(["service", "host", "agent_id", "os", "address", "runs_as", "processes", "programs", "package", "version", "ports", "last_report"]);
    expect(rows[1]).toEqual(["sshd.service", "web-01", "agent-1", "Debian 12", "10.0.0.1", "root", 3, "sshd", "openssh-server", "9.2-1", "22/tcp (exposed)", "2026-10-27T01:00:00Z"]);
  });
});

describe("service hosts table", () => {
  const host = (over: Partial<ServicePageHosts["items"][number]> = {}): ServicePageHosts["items"][number] => ({
    agent_id: "agent-1", hostname: "web-01", os: "Debian 12", processes: 3, programs: ["sshd"], run_as: "root", package: { name: "openssh-server", version: "9.2-1" },
    ports: [{ protocol: "tcp", port: 22, exposed: true }], owners_partial: false, problems: { alarms: 2, vulnerabilities: 1 }, reported_at: new Date().toISOString(), ...over,
  });

  it("shows version, processes, user, ports and problems", () => {
    const t = text(render(<HostsTable rows={[host()]} />));
    expect(t).toContain("9.2-1");
    expect(t).toContain("openssh-server");
    expect(t).toContain("as root");
    expect(t).toContain("22/tcp");
    expect(t).toContain("2 alarms · 1 vulnerability");
  });

  it("says 'not from a package', 'not collected' and a dash for problems the person may not read", () => {
    const html = render(<HostsTable rows={[host({ agent_id: "a", package: null, ports: [], owners_partial: true, problems: {} })]} />);
    expect(text(html)).toContain("not from a package");
    expect(text(html)).toContain("not collected");
    expect(html).toContain("You may not read alarms or vulnerabilities here");
    expect(text(render(<HostsTable rows={[host({ ports: [], problems: { alarms: 0, vulnerabilities: 0 } })]} />))).toContain("None");
  });

  it("warns about a report more than a day old", () => {
    const now = Date.parse("2026-10-27T12:00:00Z");
    expect(stale("2026-10-26T11:59:00Z", now)).toBe(true);
    expect(stale("2026-10-26T12:01:00Z", now)).toBe(false);
    expect(stale(null, now)).toBe(false);
    expect(render(<HostsTable rows={[host({ reported_at: "2020-01-01T00:00:00Z" })]} />)).toContain("text-warn");
  });

  it("knows root and SYSTEM and reads the segment from the URL, anything unknown being All", () => {
    expect(["root", "0", "SYSTEM", "LocalSystem", "NT AUTHORITY\\SYSTEM"].every(isRoot)).toBe(true);
    expect(["postgres", "app"].some(isRoot)).toBe(false);
    expect([segmentOf("exposed"), segmentOf("root"), segmentOf("all"), segmentOf("local"), segmentOf(null)]).toEqual(["exposed", "root", "all", "all", "all"]);
  });
});
