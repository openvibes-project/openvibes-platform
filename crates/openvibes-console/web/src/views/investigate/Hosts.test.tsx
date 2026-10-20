// The Hosts list (approved screen 16), as markup (no DOM library in vitest;
// see ui/controls.test.tsx). Filters, paging and the keyboard: hosts.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/hosts", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { HostList, HostRow } from "../../api/types";
import { HostListBody, hostFilters } from "./Hosts";

const row = (over: Partial<HostRow>): HostRow => ({
  id: "agent-1", hostname: "web-01", address: "10.0.1.3", status: "online", last_seen_at: "2026-10-20T10:00:00Z",
  os: { id: "debian", version: "12", distribution: "Debian 12", family: "linux" },
  groups: [{ id: "g1", name: "Linux", kind: "automatic" }, { id: "g2", name: "Production", kind: "rule" }], group_count: 3,
  labels: ["pci"], problems: { open_alarms: 2, critical: 1, failing: 0 }, agent: { version: "0.4.1", older: true }, ...over,
});
const list = (over: Partial<HostList> = {}): HostList => ({
  items: [row({}), row({ id: "agent-2", hostname: "win-01", address: null, os: { family: "windows", distribution: "Windows 11" }, groups: [], group_count: 0, labels: [],
    problems: { open_alarms: null, critical: 0, failing: null }, agent: { version: "0.4.2", older: false } })],
  total: 2, latest_agent_version: "0.4.2", generated_at: "2026-10-20T10:00:00Z",
  summary: { online: 9, older_agent: 4, critical: 4 },
  counts: { status: [{ value: "online", count: 9 }], os: [{ value: "linux", count: 8 }], group: [{ value: "g1", name: "Linux", kind: "automatic", count: 8 }],
    label: [{ value: "pci", count: 2 }], problems: [{ value: "alarms", count: 3 }], agent: [{ value: "older", count: 4 }] },
  ...over,
});
const render = (data: HostList, hidden: string[] = []) => renderToStaticMarkup(<HostListBody list={data} hidden={hidden} />);

describe("Hosts", () => {
  it("renders a row per host from the list", () => {
    const html = render(list());
    for (const text of ["web-01", "10.0.1.3", "Debian 12", "Linux", "win-01", "Windows 11", "0.4.1"]) expect(html).toContain(text);
    for (const header of ["Host", "OS", "Groups", "Labels", "Open problems", "Last heartbeat", "Agent"]) expect(html).toContain(`>${header}<`);
  });

  it("shows two groups, then +n for the rest", () => {
    expect(render(list())).toMatch(/Linux<\/span>.*Production<\/span>.*\+1/);
  });

  it("marks an agent older than the latest release amber, saying so", () => {
    const html = render(list());
    expect(html).toMatch(/class="mono warn-text" title="Older than the latest agent release \(0\.4\.2\)">0\.4\.1</);
    expect(html).toMatch(/class="mono" title="The latest agent release \(0\.4\.2\)">0\.4\.2</);
  });

  it("marks none amber while the latest release is unknown", () => {
    const html = render(list({ latest_agent_version: null, items: [row({ agent: { version: "0.4.1", older: null } })] }));
    expect(html).not.toContain("warn-text");
    expect(html).toContain('title="The latest agent release is not known: the update check is off or offline"');
  });

  it("shows — for a problem kind the viewer cannot read on that host", () => {
    const html = render(list({ items: [row({ problems: { open_alarms: null, critical: 0, failing: null } })] }));
    expect(html).toMatch(/title="You can’t see open alarms on this host">—</);
    expect(html).toMatch(/title="You can’t see failing checks on this host">—</);
  });

  it("leaves hidden columns out", () => {
    const html = render(list(), ["labels", "os"]);
    expect(html).not.toContain(">Labels<");
    expect(html).not.toContain(">OS<");
    expect(html).not.toContain("pci");
    expect(html).toContain(">Groups<");
  });

  it("reads the summary line", () => {
    expect(render(list())).toContain("9 online · 4 with an older agent · 4 with critical vulnerabilities");
  });

  it("builds each filter's values from the counts, in the URL spelling", () => {
    const filters = hostFilters(list());
    expect(filters.map((f) => f.param)).toEqual(["status", "os", "group", "label", "problems", "agent"]);
    expect(filters.find((f) => f.param === "group")?.values).toEqual([{ value: "g1", label: "Linux", count: 8 }]);
    expect(filters.find((f) => f.param === "problems")?.values).toEqual([{ value: "alarms", label: "Has open alarms", count: 3 }]);
    expect(filters.find((f) => f.param === "os")?.values).toEqual([{ value: "linux", label: "Linux", count: 8 }]);
  });
});
