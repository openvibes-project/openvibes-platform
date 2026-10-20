// The group page (approved screens 10, 10b, 10c). Vitest runs in node with no
// DOM library (see ui/controls.test.tsx): the page is checked as markup from
// react-dom/server, edits are the reducer (groupState.test.ts), and saves go
// through a stubbed fetch.
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { GroupHost, HostGroupDetail, Permission, Session } from "../../../api/types";
import { SessionContext } from "../../../app/session";
import { PreviewNote } from "./badges";
import { saveGroup } from "./groupApi";
import { GroupBody } from "./GroupPage";
import { NewGroupForm } from "./NewGroup";
import { blankDraft, fromGroup, patchBody, reduce } from "./groupState";

const detail = (over: Partial<HostGroupDetail> = {}): HostGroupDetail => ({
  asset_group_id: "g-win", name: "WindowsServers", kind: "rule", description: "Windows servers the Windows team runs.",
  conditions: [{ field: "os_family", values: ["windows"] }, { field: "hostname", negate: true, values: ["*test*"] }],
  membership: "Hosts where OS family is Windows and hostname does not match *test*", picked: 0, hosts: 4, online: 3,
  open_alarms: 3, critical: 4, roles: [{ role_id: "r-win", name: "Windows lead" }], people: 2, upgraded_from_tags: false, version: 5,
  changed_at: "2026-10-16T09:00:00Z", changed_by: "u-alex",
  recent: [
    { action: "host_group.updated", actor: "u-alex", at: "2026-10-16T09:00:00Z", detail: {} },
    { action: "host_group.created", actor: "u-me", at: "2026-10-02T09:00:00Z", detail: {} },
  ],
  ...over,
});
const winHost: GroupHost = { agent_id: "agent.1", hostname: "win-dc-01", distribution: "Windows Server 2022", last_address: "10.0.1.10", labels: ["hq"],
  last_seen_at: "2026-10-16T09:00:00Z", online: false, open_alarms: 2, critical: 0, why: "Matches the rule" };

const session = { principal: { id: "u-me", display_name: "Me" }, capabilities: [] } as unknown as Session;
type Access = { held?: (p: Permission) => boolean; everywhere?: boolean };
const render = (group: HostGroupDetail, hosts: GroupHost[] = [winHost], access: Access = {}, editing = false, reloading = false) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session, demo: false, can: access.held ?? (() => true), canEverywhere: () => access.everywhere ?? true }}>
    <GroupBody group={group} hosts={hosts} names={new Map([["u-alex", "Alex Admin"]])} reloading={reloading}
      {...(editing ? { initial: fromGroup(group, hosts.map((h) => ({ agent_id: h.agent_id, hostname: h.hostname ?? h.agent_id }))) } : {})} />
  </SessionContext.Provider>,
);

afterEach(() => vi.unstubAllGlobals());

describe("group page", () => {
  it("a rule group: header, details, rule, recent changes and hosts", () => {
    const html = render(detail());
    expect(html).toContain("Settings</a> › <a");
    expect(html).toContain("4 hosts · 3 online · used by 1 role · 2 people reach it");
    expect(html).toContain("Rule: stays up to date");
    expect(html).toMatch(/>Where<.*OS family.*is.*Windows/);
    expect(html).toMatch(/>and<.*Hostname.*does not match.*\*test\*/);
    expect(html).toContain("Changed a host group");
    expect(html).toContain("Alex Admin");
    expect(html).toContain("you ·");
    expect(html).toContain('href="/settings/roles/r-win"');
    expect(html).toContain("win-dc-01");
    expect(html).toMatch(/class="warn-text"/);
    expect(html).toContain("2 alarms");
    expect(html).not.toContain("Remove this condition");
  });

  it("editing shows the editor controls", () => {
    const html = render(detail({ conditions: [{ field: "ip", values: ["10.0.0.0/16"] }] }), [winHost], {}, true);
    expect(html).toContain("Stop editing");
    expect(html).toContain("Editing");
    expect(html).toContain('aria-label="Remove this condition"');
    expect(html).toContain("+ Add condition");
    expect(html).toContain("Rules use what agents report: OS family, distribution, hostname and IP address. Labels never count.");
    expect(html).toContain("The address OpenVIBES sees; behind NAT this is the router.");
    expect(html).toContain("Save changes");
  });

  it("an automatic group has the callout", () => {
    const html = render(detail({ kind: "automatic", roles: [], people: 0, changed_at: null, changed_by: null }));
    expect(html).toContain("Made by OpenVIBES from what agents report. Editing it makes it yours: OpenVIBES won&#x27;t change it again. Deleting it is remembered; it won&#x27;t come back.");
    expect(html).toContain("Automatic: made by OpenVIBES");
    expect(html).toContain("Never by hand");
    expect(html).toContain("No role uses this group yet. Choose it in a role&#x27;s Hosts.");
  });

  it("a manual group made from tags offers Turn into a rule", () => {
    const manual = detail({ kind: "manual", conditions: [], upgraded_from_tags: true, membership: "1 host picked by hand", picked: 1 });
    const html = render(manual, [{ ...winHost, why: "Picked by hand" }]);
    expect(html).toContain("This group was made from tags. You can turn it into a rule group.");
    expect(html).toContain("Turn into a rule");
    expect(html).toContain("Hosts picked by hand. New hosts are never added by themselves.");
    expect(html).toContain("Manual: hand-picked");
    expect(render(manual, [{ ...winHost, why: "Picked by hand" }], {}, true)).toContain("Search hosts to add");
  });

  it("write controls are disabled without every host, and hidden without host_groups.manage", () => {
    const all = render(detail());
    expect(all).toMatch(/<button[^>]*>Edit<\/button>/);
    expect(all).toContain('aria-label="More actions"');
    const some = render(detail(), [winHost], { everywhere: false });
    expect(some).toMatch(/<button[^>]*disabled=""[^>]*title="Changing host groups needs access to every host"[^>]*>Edit<\/button>/);
    expect(some).toContain("Changing host groups needs access to every host.</p>");
    expect(some).toMatch(/aria-describedby="[^"]+"[^>]*>Edit</);
    expect(some).not.toContain("Turn into a rule");
    const none = render(detail(), [winHost], { held: (p) => p !== "host_groups.manage" });
    expect(none).not.toContain(">Edit<");
    expect(none).not.toContain('aria-label="More actions"');
  });

  it("without hosts.read the counts say what you can see", () => {
    const html = render(detail({ kind: "manual", conditions: [], hosts: 0, online: 0, picked: 0, membership: "0 hosts picked by hand" }), [],
      { held: (p) => p !== "hosts.read", everywhere: false });
    expect(html).toContain("No hosts you can see");
    expect(html).not.toContain("0 hosts picked by hand");
    expect(html).toContain("No host matches yet.");
  });

  it("Save waits while the group or its hosts reload", () => {
    const html = render(detail(), [winHost], {}, true, true);
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Save changes<\/button>/);
    expect(html).toContain("Reloading…");
    expect(render(detail(), [winHost], {}, true)).not.toMatch(/disabled=""[^>]*>Save changes/);
  });

  it("a viewer who sees some hosts gets counts of what they can see", () => {
    const html = render(detail({ hosts: 2, online: 1 }), [winHost], { everywhere: false });
    expect(html).toContain("2 hosts you can see · 1 online · used by 1 role");
  });

  it("each host says why it is in the group", () => {
    expect(render(detail())).toContain("Windows Server 2022</span><span class=\"subtle\">Matches the rule</span>");
  });

  it("picks cannot be edited until every pick is loaded", () => {
    const manual = detail({ kind: "manual", conditions: [], membership: "3 hosts picked by hand", picked: 3 });
    const html = render(manual, [{ ...winHost, why: "Picked by hand" }], {}, true);
    expect(html).toContain("Only 1 of 3 picked hosts could be loaded, so the picks cannot be changed here.");
    expect(html).not.toContain("Search hosts to add");
    expect(html).not.toContain('aria-label="Remove win-dc-01"');
  });

  it("a new group without host_groups.manage says why it cannot be created", () => {
    const html = renderToStaticMarkup(
      <SessionContext.Provider value={{ session, demo: false, can: (p) => p !== "host_groups.manage", canEverywhere: () => true }}>
        <NewGroupForm initial={blankDraft("rule")} />
      </SessionContext.Provider>,
    );
    expect(html).toContain("Changing host groups needs the Manage host groups permission");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Create group<\/button>/);
  });

  it("a failed preview says so instead of looking like no change", () => {
    expect(renderToStaticMarkup(<PreviewNote preview="failed" />)).toContain("Preview unavailable");
  });

  it("the preview names hosts and people", () => {
    const html = renderToStaticMarkup(<PreviewNote preview={{ joins: [{ agent_id: "a", hostname: "web-01" }], joins_total: 1, leaves: [], leaves_total: 0,
      gains: [{ user_id: "u", username: "w", display_name: "Wendy Ward" }], loses: [], people_total: 1, overrides_removed: 0 }} />);
    expect(html.replace(/<\/?span>/g, "")).toContain("If you save: <b>+1</b> (web-01). Wendy Ward gains access to them.");
  });

  it("a rename sends PATCH with the name and version only", async () => {
    const fetch = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    const base = fromGroup(detail(), []);
    await saveGroup("g-win", patchBody(reduce(base, { type: "name", name: "Windows" }), base, 5));
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/host-groups/g-win");
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body as string)).toEqual({ name: "Windows", version: 5 });
  });
});
