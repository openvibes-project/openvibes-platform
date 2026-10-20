// The host's page (approved screen 17), as markup: no DOM library in vitest
// (see ui/controls.test.tsx); the actions are covered by e2e/demo/host-page.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { Agent, HostSummary, Session } from "../../../api/types";
import { SessionContext } from "../../../app/session";
import { ago } from "../../../ui/format";
import { HostView, shortDate } from "./HostPage";

const now = Date.now();
const iso = (ms: number) => new Date(ms).toISOString();
const summary = (over: Partial<HostSummary> = {}): HostSummary => ({
  host: {
    id: "agent-00005", hostname: "web-01", status: "online", address: "10.0.1.5",
    os: { id: "debian", version: "12", distribution: "Debian 12", family: "linux" }, running_kernel: "6.1.0", scanner_version: "0.4.2",
    agent_older: false, enrolled_at: "2026-10-03T09:00:00Z", revoked_at: null, last_seen_at: iso(now - 120_000), inventory_at: null, capabilities: ["findings"],
  },
  tiles: { open_alarms: 3, compliance_failing: 7, vulnerabilities: 12, software: 412 },
  protection: { threat_alarms: { state: "on", source: "ebpf", fault: false }, last_test: { alarm_at: null, finding_at: null } },
  groups: [{ id: "grp-prod", name: "Production", kind: "rule" }], labels: ["pci"],
  certificates: [{ serial: "01AB", issued_at: "2026-10-03T09:00:00Z", not_before: "2026-10-03T09:00:00Z", not_after: "2027-10-03T09:00:00Z" }], certificate_count: 1,
  top_alarms: { total: 3, items: [{ id: 7, rule_id: "r-1", message: "A web server started a shell", severity: "high", last_seen: iso(now - 60_000) }] },
  top_vulnerabilities: { total: 12, items: [{ advisory: "DSA-5501-1", severity: "critical", kev: true }] },
  top_failing: { total: 7, items: [{ rule_set_id: "baseline", rule_id: "ssh-root", severity: "high", message: "SSH allows root login" }] },
  inventory: { packages: 412, listening_ports: 9, exposed_ports: 4, services: 23 },
  can: { label: true, revoke: true, export: true, add_to_case: true, ask: true },
  ...over,
});
const agent = { id: "agent-00005", hostname: "web-01", status: "active", rule_sets: [], capabilities: [] } as unknown as Agent;
const session = { principal: { id: "u-me", display_name: "Me" }, capabilities: [] } as unknown as Session;
const render = (s: HostSummary) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session, demo: false, can: () => true, canEverywhere: () => true }}>
    <HostView summary={s} agent={agent} />
  </SessionContext.Provider>,
).replace(/<!-- -->/g, "");
const text = (html: string) => html.replace(/<[^>]+>/g, "");

describe("host page", () => {
  it("reads the header facts line", () => {
    const html = render(summary());
    expect(html).toContain("web-01");
    expect(text(html)).toContain(`agent-00005 · Debian 12 · 10.0.1.5 · 0.4.2 · ${ago(iso(now - 120_000))} · enrolled ${shortDate("2026-10-03T09:00:00Z")}`);
    // In an English locale, the line the brief names.
    if (shortDate("2026-10-03T09:00:00Z") === "3 Oct" && ago(iso(now - 120_000)) === "2 min ago") {
      expect(text(html)).toContain("agent-00005 · Debian 12 · 10.0.1.5 · 0.4.2 · 2 min ago · enrolled 3 Oct");
    }
  });

  it("links the four tiles to their full lists", () => {
    const html = render(summary());
    for (const href of ["/alarms?host=agent-00005", "/compliance?host=agent-00005", "/vulnerabilities?host=agent-00005", "/hosts/agent-00005/software"]) {
      expect(html).toMatch(new RegExp(`<a [^>]*detail-tile[^>]*href="${href.replace("?", "\\?")}"|<a [^>]*href="${href.replace("?", "\\?")}"[^>]*detail-tile`));
    }
    expect(html).toContain('aria-label="Software: 412"');
  });

  it("leaves out each card and tile whose section is null", () => {
    const html = render(summary({
      tiles: { open_alarms: null, compliance_failing: null, vulnerabilities: null, software: 412 },
      top_alarms: null, top_vulnerabilities: null, top_failing: null,
    }));
    expect(html).not.toContain("Open alarms");
    expect(html).not.toContain("Compliance failing");
    expect(html).not.toContain("/vulnerabilities?host=");
    expect(html).toContain('aria-label="Software: 412"');
    expect(html).toContain("Software, ports and services");
  });

  it("leaves out each action its can flag refuses", () => {
    const all = render(summary());
    for (const s of [" Export</button>", "Add to case", "Ask about this", 'aria-label="More actions"', 'aria-label="Add a label"']) expect(all).toContain(s);
    const none = render(summary({ can: { label: false, revoke: false, export: false, add_to_case: false, ask: false } }));
    for (const s of [" Export</button>", "Add to case", "Ask about this", 'aria-label="More actions"', 'aria-label="Add a label"', "Remove label"]) expect(none).not.toContain(s);
    expect(none).toContain("Compare");
  });

  it("links Show all n to the filtered list", () => {
    const html = render(summary());
    expect(html).toMatch(/<a [^>]*href="\/vulnerabilities\?host=agent-00005"[^>]*>Show all 12 vulnerabilities<\/a>/);
    expect(html).toMatch(/<a [^>]*href="\/alarms\?host=agent-00005"[^>]*>Show all 3 alarms<\/a>/);
    expect(html).toMatch(/<a [^>]*href="\/compliance\?host=agent-00005"[^>]*>Show all 7 checks<\/a>/);
    expect(html).toMatch(/<a [^>]*href="\/hosts\/agent-00005\/ports"[^>]*>Show all 9 ports<\/a>/);
    expect(html).toMatch(/<a [^>]*href="\/hosts\/agent-00005\/services"[^>]*>Show all 23 services<\/a>/);
  });

  it("keeps everything the panel showed: details, protection, groups, labels, certificates", () => {
    const html = text(render(summary()));
    for (const s of ["Details", "Running kernel", "6.1.0", "Capabilities", "findings", "Protection", "Threat alarms", "eBPF", "Last test",
      "openvibes-test alarm", "Rule sets", "Groups and labels", "Production", "pci", "Certificates", "01AB", "Current"]) expect(html).toContain(s);
  });
});
