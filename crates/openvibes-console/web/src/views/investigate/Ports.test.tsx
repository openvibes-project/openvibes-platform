// The Ports list (approved screen 19), as markup (no DOM library in vitest;
// see ui/controls.test.tsx). Filters, saved views, columns and paging in a
// browser: e2e/demo/port-list.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/ports", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { PortList, PortListRow } from "../../api/types";
import { LOOK, PortListBody, apiQuery, portFilters, portOf } from "./Ports";

const row = (over: Partial<PortListRow> = {}): PortListRow => ({
  protocol: "tcp", port: 22, name: "SSH", hosts: 12, exposed_hosts: 3, services: ["sshd.service"], owners_missing: false,
  groups: [{ id: "g1", name: "Web", kind: "rule", hosts: 8 }, { id: "g2", name: "Linux", kind: "automatic", hosts: 12 }], groups_total: 4,
  week_added: 2, week_removed: 1, look: [], ...over,
});
const unusual = row();
delete unusual.name;
const list = (over: Partial<PortList> = {}): PortList => ({
  items: [
    row(),
    row({ protocol: "tcp", port: 5432, name: "PostgreSQL", hosts: 2, exposed_hosts: 1, services: ["postgresql.service"], groups: [], groups_total: 0, week_added: 0, week_removed: 0,
      look: ["database_exposed", "new_unusual"] }),
    { ...unusual, protocol: "udp", port: 9999, hosts: 1, exposed_hosts: 0, services: [], owners_missing: true, groups: [], groups_total: 0, week_added: 1, week_removed: 0, look: ["new_unusual"] },
  ],
  total: 3, generated_at: "2026-10-27T10:00:00Z",
  summary: { exposed: 2, new_this_week: 2, need_a_look: 2, reporting_hosts: 14 },
  counts: {
    exposure: [{ value: "exposed", count: 2 }, { value: "local", count: 1 }], protocol: [{ value: "tcp", count: 2 }, { value: "udp", count: 1 }],
    changes: [{ value: "new", count: 2 }, { value: "look", count: 2 }], group: [{ value: "g1", name: "Web", kind: "rule", count: 2 }],
    service: [{ value: "sshd.service", count: 1 }, { value: "~none", count: 1 }],
  },
  ...over,
});
const render = (data: PortList, hidden: string[] = [], offset = 0) =>
  renderToStaticMarkup(<PortListBody list={data} hidden={hidden} offset={offset} />).replace(/<!-- -->/g, "");
const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/&#x27;/g, "'").replace(/\s+/g, " ");

describe("Ports list", () => {
  it("asks the API only for what it reads, one page at a time", () => {
    expect(apiQuery(new URLSearchParams("q=ssh&exposure=exposed&protocol=tcp&group=g1&service=~none&changes=look&host=a%2F1&sort=week&dir=desc&offset=50&bad=1&exposed=true")))
      .toBe("q=ssh&exposure=exposed&protocol=tcp&group=g1&service=%7Enone&changes=look&host=a%2F1&sort=week&dir=desc&offset=50&limit=50");
    expect(apiQuery(new URLSearchParams())).toBe("limit=50");
  });

  it("renders screen 19's columns, the port a real link to its page", () => {
    const html = render(list());
    for (const header of ["Port", "Hosts", "Exposed", "Services", "Groups", "This week", "Needs a look"]) expect(html).toContain(`>${header}<`);
    expect(html).toContain('href="/ports/22/tcp"');
    expect(html).toContain('href="/ports/9999/udp"');
    expect(text(html)).toContain("SSH");
    expect(html).toContain("Not a usual port");
    expect(html).toContain("sshd.service");
  });

  it("says exposure, this week and Needs a look the way the rulings do", () => {
    const t = text(render(list()));
    expect(t).toContain("3 hosts");
    expect(t).toContain("local only");
    expect(t).toContain("+2 hosts");
    expect(t).toContain("−1 host");
    expect(t).toContain("+1 host");
    expect(t).toContain("No change");
    expect(t).toContain(LOOK["database_exposed"]);
    // The first code shows and the rest count.
    expect(t).toContain("+1");
    expect(t).not.toContain(LOOK["new_unusual"] + "+");
  });

  it("shows the groups, three at most with the rest counted, and 'Owner not collected'", () => {
    const html = render(list());
    expect(html).toContain("Web");
    expect(html).toContain('title="4 groups"');
    expect(text(html)).toContain("Owner not collected");
    expect(html).toContain("In no group");
  });

  it("leaves out a hidden column but never Port", () => {
    const html = render(list(), ["port", "hosts", "services", "groups", "week", "look"]);
    expect(html).toContain(">Port<");
    for (const header of ["Hosts", "Services", "Groups", "This week", "Needs a look"]) expect(html).not.toContain(`>${header}<`);
    expect(html).toContain(">Exposed<");
  });

  it("summarises from the server's counts and the reporting hosts", () => {
    expect(text(render(list()))).toContain("2 ports reachable from the network · 2 new this week · 2 need a look · from 14 hosts' last reports");
    expect(text(render(list({ summary: { exposed: 1, new_this_week: 0, need_a_look: 0, reporting_hosts: 1 } })))).toContain("1 port reachable from the network · 0 new this week · 0 need a look · from 1 host's last report");
  });

  it("pages by offset", () => {
    expect(render(list({ total: 120 }), [], 50)).toContain("51–53 of 120");
    expect(render(list())).not.toContain("Pages");
  });

  it("offers the filters the server counted, with their labels, and a Host chip only while set", () => {
    const filters = portFilters(list(), { host: null, hostName: undefined });
    expect(filters.map((f) => f.param)).toEqual(["exposure", "protocol", "changes", "group", "service", "host"]);
    expect(filters.find((f) => f.param === "exposure")?.values).toEqual([{ value: "exposed", label: "Exposed", count: 2 }, { value: "local", label: "Local only", count: 1 }]);
    expect(filters.find((f) => f.param === "service")?.values.map((v) => v.label)).toEqual(["sshd.service", "Owner not collected"]);
    expect(filters.find((f) => f.param === "host")?.values).toEqual([]);
    expect(portFilters(list(), { host: "agent-1", hostName: "web-01" }).find((f) => f.param === "host")?.values).toEqual([{ value: "agent-1", label: "web-01", count: 3 }]);
    expect(portFilters(undefined, { host: null, hostName: undefined }).every((f) => f.values.length === 0)).toBe(true);
  });

  it("reads a port from /ports/{port}/{protocol}", () => {
    expect(portOf("/ports/22/tcp")).toEqual(["tcp", 22]);
    expect(portOf("/ports/53/udp")).toEqual(["udp", 53]);
    for (const bad of ["/ports/22", "/ports/22/icmp", "/ports/0/tcp", "/ports/22/tcp/x", "/ports/%E0%A4%A/tcp", "/ports/"]) expect(portOf(bad)).toBeNull();
  });
});
