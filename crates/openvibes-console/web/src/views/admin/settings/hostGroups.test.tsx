// Settings › Host groups as markup (vitest runs in node, no DOM library).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/settings", search: "?tab=host-groups" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

const base = { description: "", picked: 0, hosts: 0, online: 0, open_alarms: 0, critical: 0, roles: [], people: 0, upgraded_from_tags: false, version: 1 };
vi.mock("../../../api/client", () => ({
  apiMessage: () => "", invalidate() {}, request: async () => ({}),
  useResource: () => ({ loading: false, data: [
    { ...base, asset_group_id: "g-man", name: "Pilot hosts", kind: "manual", conditions: [], membership: "3 hosts picked by hand", picked: 3, hosts: 3, online: 2 },
    { ...base, asset_group_id: "g-win", name: "WindowsServers", kind: "rule", conditions: [{ field: "os_family", values: ["windows"] }],
      membership: "Hosts where OS family is Windows", hosts: 4, online: 3, open_alarms: 3, critical: 4, roles: [{ role_id: "r", name: "Windows lead" }], people: 2 },
    { ...base, asset_group_id: "g-deb", name: "Debian 12", kind: "automatic", conditions: [{ field: "distribution", values: ["debian 12"] }], membership: "Hosts where distribution is Debian 12" },
  ] }),
}));

vi.mock("../../../app/nav", () => ({
  nav: { view() {}, href: () => "#", setParams() {}, open() {} },
  useLocation: () => ({ view: "/settings", params: new URLSearchParams("tab=host-groups"), panels: [] }),
  useTopPanel: () => undefined,
}));

import { SessionContext } from "../../../app/session";
import { HostGroups } from "./HostGroups";

describe("host groups list", () => {
  it("shows the kinds apart with membership, hosts, problems and reach", () => {
    const html = renderToStaticMarkup(
      <SessionContext.Provider value={{ session: undefined, demo: false, can: () => true, canEverywhere: () => true }}><HostGroups /></SessionContext.Provider>,
    );
    expect(html).toContain("New group");
    expect(html).toContain("Filter groups, rules or hosts…");
    // Automatic first, then rule, then manual.
    expect(html.indexOf("Debian 12")).toBeLessThan(html.indexOf("WindowsServers"));
    expect(html.indexOf("WindowsServers")).toBeLessThan(html.indexOf("Pilot hosts"));
    expect(html).toContain("Hosts where OS family is Windows");
    expect(html).toContain("3 hosts picked by hand");
    expect(html).toContain("4 hosts");
    expect(html).toContain("3 online");
    expect(html).toContain("3 alarms");
    expect(html).toContain("4 critical");
    expect(html).toContain("None open");
    expect(html).toContain("Windows lead");
    expect(html).toContain("2 people");
    expect(html).toContain("No role yet");
    expect(html).toContain("Nobody reaches it");
  });
});
