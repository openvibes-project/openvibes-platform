// The Services list (approved screen 21), as markup (no DOM library in vitest;
// see ui/controls.test.tsx). Filters, saved views, columns and paging in a
// browser: e2e/demo/service-list.spec.ts.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/services", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { ServiceList, ServiceListRow } from "../../api/types";
import { LOOK, ServiceListBody, apiQuery, serviceFilters, unitOf } from "./Services";

const row = (over: Partial<ServiceListRow> = {}): ServiceListRow => ({
  unit: "sshd.service", name: "OpenSSH server", usual_use: "Secure remote login", hosts: 12, root_hosts: 12, package_hosts: 12, exposed_hosts: 3, listening_hosts: 12,
  run_as: ["root"], programs: ["sshd"], package: "openssh-server", groups: [{ id: "g1", name: "Web", kind: "rule", hosts: 8 }], groups_total: 1,
  ports: [{ protocol: "tcp", port: 22, exposed: true, hosts: 12 }], ports_total: 1, week_added: 2, week_removed: 1, look: [], ...over,
});
const unusual = row();
delete unusual.name;
delete unusual.usual_use;
const list = (over: Partial<ServiceList> = {}): ServiceList => ({
  items: [
    row(),
    row({ unit: "postgresql.service", name: "PostgreSQL", hosts: 4, root_hosts: 0, package_hosts: 3, exposed_hosts: 1, run_as: ["postgres"], programs: ["postgres"], package: "postgresql", groups: [],
      groups_total: 0, ports: [{ protocol: "tcp", port: 5432, exposed: true, hosts: 4 }, { protocol: "tcp", port: 5433, exposed: false, hosts: 1 }], ports_total: 6, week_added: 0, week_removed: 0,
      look: ["database_exposed", "new_unusual"] }),
    { ...unusual, unit: "build.service", hosts: 2, root_hosts: 1, package_hosts: 0, exposed_hosts: 0, run_as: ["root", "ci"], programs: [], package: null, groups: [], groups_total: 0, ports: [],
      ports_total: 0, week_added: 0, week_removed: 0, look: ["root_unpackaged"] },
  ],
  total: 3, generated_at: "2026-10-27T10:00:00Z",
  summary: { root: 2, exposed: 2, not_packaged: 2, new_this_week: 1, need_a_look: 2, reporting_hosts: 14 },
  counts: {
    runs_as: [{ value: "root", count: 2 }, { value: "other", count: 1 }], listens: [{ value: "exposed", count: 2 }, { value: "local", count: 0 }, { value: "none", count: 1 }],
    packaged: [{ value: "yes", count: 1 }, { value: "no", count: 2 }], changes: [{ value: "new", count: 1 }, { value: "look", count: 2 }], group: [{ value: "g1", name: "Web", kind: "rule", count: 1 }],
  },
  ...over,
});
const render = (data: ServiceList, hidden: string[] = [], offset = 0) =>
  renderToStaticMarkup(<ServiceListBody list={data} hidden={hidden} offset={offset} />).replace(/<!-- -->/g, "");
const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/&#x27;/g, "'").replace(/\s+/g, " ");

describe("Services list", () => {
  it("asks the API only for what it reads, one page at a time", () => {
    expect(apiQuery(new URLSearchParams("q=ssh&runs_as=root&listens=exposed&packaged=no&group=g1&changes=look&host=a%2F1&sort=week&dir=desc&offset=50&bad=1&exposed=true")))
      .toBe("q=ssh&runs_as=root&listens=exposed&packaged=no&group=g1&changes=look&host=a%2F1&sort=week&dir=desc&offset=50&limit=50");
    expect(apiQuery(new URLSearchParams())).toBe("limit=50");
  });

  it("renders screen 21's columns, the unit a real link to its page", () => {
    const html = render(list());
    for (const header of ["Service", "Hosts", "Runs as", "Ports", "Programs and package", "This week", "Needs a look"]) expect(html).toContain(`>${header}<`);
    expect(html).toContain('href="/services/sshd.service"');
    expect(html).toContain('href="/services/postgresql.service"');
    expect(text(html)).toContain("OpenSSH server");
    expect(html).toContain("Not a usual service");
  });

  it("says runs as, ports, package, this week and Needs a look the way the rulings do", () => {
    const t = text(render(list()));
    expect(t).toContain("root on 1 of 2");
    expect(t).toContain("postgres");
    expect(t).toContain("22/tcp");
    expect(t).toContain("+2");
    expect(t).toContain("not from a package");
    expect(t).toContain("not on 1 of 4");
    expect(t).toContain("+2 hosts");
    expect(t).toContain("−1 host");
    expect(t).toContain("No change");
    expect(t).toContain(LOOK["database_exposed"]);
    expect(t).toContain(LOOK["root_unpackaged"]);
    // The first code shows and the rest count.
    expect(t).not.toContain(LOOK["new_unusual"] + "+");
  });

  it("links an owned port to its page, exposed ones in amber", () => {
    const html = render(list());
    expect(html).toContain('href="/ports/5432/tcp"');
    expect(html).toMatch(/badge--warn[^>]*>5432\/tcp/);
  });

  it("leaves out a hidden column but never Service", () => {
    const html = render(list(), ["service", "hosts", "runs_as", "ports", "package", "week", "look"]);
    expect(html).toContain(">Service<");
    for (const header of ["Hosts", "Runs as", "Ports", "Programs and package", "This week", "Needs a look"]) expect(html).not.toContain(`>${header}<`);
  });

  it("summarises from the server's counts and the reporting hosts", () => {
    expect(text(render(list()))).toContain("2 services run as root · 2 listen on an exposed port · 2 not from a package · 1 new this week · 2 need a look · from 14 hosts' last reports");
    expect(text(render(list({ summary: { root: 1, exposed: 1, not_packaged: 0, new_this_week: 0, need_a_look: 0, reporting_hosts: 1 } })))).toContain("1 service runs as root · 1 listens on an exposed port");
  });

  it("pages by offset", () => {
    expect(render(list({ total: 120 }), [], 50)).toContain("51–53 of 120");
    expect(render(list())).not.toContain("Pages");
  });

  it("offers the filters the server counted, with their labels, and a Host chip only while set", () => {
    const filters = serviceFilters(list(), { host: null, hostName: undefined });
    expect(filters.map((f) => f.param)).toEqual(["runs_as", "listens", "packaged", "changes", "group", "host"]);
    expect(filters.find((f) => f.param === "runs_as")?.values).toEqual([{ value: "root", label: "Root or SYSTEM", count: 2 }, { value: "other", label: "Another user", count: 1 }]);
    expect(filters.find((f) => f.param === "host")?.values).toEqual([]);
    expect(serviceFilters(list(), { host: "agent-1", hostName: "web-01" }).find((f) => f.param === "host")?.values).toEqual([{ value: "agent-1", label: "web-01", count: 3 }]);
    expect(serviceFilters(undefined, { host: null, hostName: undefined }).every((f) => f.values.length === 0)).toBe(true);
  });

  it("reads a unit from /services/{unit}", () => {
    expect(unitOf("/services/sshd.service")).toBe("sshd.service");
    expect(unitOf("/services/openvpn-server%40server.service")).toBe("openvpn-server@server.service");
    for (const bad of ["/services/", "/services/a/b", "/services/%E0%A4%A", "/services/a%00b"]) expect(unitOf(bad)).toBeNull();
  });
});
