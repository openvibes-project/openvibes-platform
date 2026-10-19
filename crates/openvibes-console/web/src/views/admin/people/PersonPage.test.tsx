// The person page. Vitest runs in node with no DOM library (see ui/controls.test.tsx):
// grouping and refusals are pure helpers, the page is checked as markup from
// react-dom/server, and role changes go through a stubbed fetch.
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import { subscribe } from "../../../api/client";
import type { PersonView, Session } from "../../../api/types";
import { SessionContext } from "../../../app/session";
import { PersonBody } from "./PersonPage";
import { LAST_ADMIN, accessGroups, changeRole, personActions, refusal } from "./people";

const wendy: PersonView = {
  user_id: "u-wendy", username: "wendy", display_name: "Wendy Ward", email: "wendy@corp.example", enabled: true, auth_source: "password",
  last_sign_in_at: null, created_at: "2026-10-04T10:00:00Z",
  roles: [
    { role_id: "r-win", name: "Windows lead", description: "", builtin: false, members: 1, version: 1, permissions: ["hosts.read", "alarms.triage"], reach: { kind: "groups", groups: [{ asset_group_id: "g-win", name: "WindowsServers" }] } },
    { role_id: "r-view", name: "Viewer", description: "", builtin: false, members: 3, version: 1, permissions: ["alarms.read"], reach: { kind: "all" } },
  ],
  access: [
    { permission: "alarms.read", label: "View alarms", area: "Alarms", applies: "all", groups: [], from_role: "Viewer" },
    { permission: "alarms.triage", label: "Triage alarms", area: "Alarms", applies: "groups", groups: [{ asset_group_id: "g-win", name: "WindowsServers" }], from_role: "Windows lead" },
    { permission: "assistant.use", label: "Use the assistant", area: "Assistant", applies: "platform", groups: [], from_role: "Windows lead" },
  ],
  recent: [{ action: "alarm.triaged", target: "a-1", at: "2026-10-16T09:00:00Z" }],
};

const session = (id: string) => ({ principal: { id, display_name: "Alex" }, capabilities: [] }) as unknown as Session;
/** Rendered for someone holding every permission; `me` is the signed-in user's id. */
const render = (person: PersonView, me = "u-alex", error?: string) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session: session(me), demo: false, can: () => true, canEverywhere: () => true }}>
    <PersonBody person={person} error={error} onError={() => {}} />
  </SessionContext.Provider>,
);

afterEach(() => vi.unstubAllGlobals());

describe("person page", () => {
  it("groups access by where it applies", () => {
    expect(accessGroups(wendy.access).map((g) => g.title)).toEqual(["On all hosts", "Only on WindowsServers", "Across the platform"]);
    // Held on all hosts already: not repeated under the group.
    const twice = accessGroups([...wendy.access, { permission: "alarms.read", label: "View alarms", area: "Alarms", applies: "groups", groups: [{ asset_group_id: "g-win", name: "WindowsServers" }], from_role: "Windows lead" }]);
    expect(twice.find((g) => g.title === "Only on WindowsServers")?.lines.map((l) => l.permission)).toEqual(["alarms.triage"]);
    const html = render(wendy);
    const at = (s: string) => html.indexOf(s);
    expect(at("On all hosts")).toBeGreaterThan(-1);
    expect(at("On all hosts")).toBeLessThan(at("Only on WindowsServers"));
    expect(at("Only on WindowsServers")).toBeLessThan(at("Across the platform"));
    expect(html).toContain("View alarms · from Viewer");
    expect(html).toContain("Triage alarms · from Windows lead");
    expect(html).toContain("2 roles · 3 permissions · never signed in");
  });

  it("Add role sends PUT and refreshes", async () => {
    const fetch = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetch);
    const refreshed = vi.fn();
    const stop = subscribe(refreshed);
    await changeRole("u-wendy", "r-ops", true);
    stop();
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/users/u-wendy/roles/r-ops");
    expect(init.method).toBe("PUT");
    expect(refreshed).toHaveBeenCalled();
  });

  it("the last Administrator message is shown on 409", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ code: "last_administrator", title: "Someone else must hold Administrator first" }), { status: 409 })));
    const error = await changeRole("u-wendy", "admin", false).then(() => undefined, (e: unknown) => refusal(e, "x"));
    expect(error).toBe("This is the last Administrator. Give someone else the Administrator role first.");
    expect(render(wendy, "u-alex", LAST_ADMIN)).toMatch(/role="alert"[^>]*>.*This is the last Administrator\./);
  });

  it("own page has no Disable", () => {
    expect(personActions(wendy, false, true).map((a) => a.label)).toEqual(["Reset password…", "Disable user…"]);
    expect(personActions(wendy, true, true)).toEqual([]);
    expect(render(wendy, "u-alex")).toContain('aria-label="More actions"');
    const own = render(wendy, "u-wendy");
    expect(own).not.toContain('aria-label="More actions"');
    expect(own).not.toContain(">Remove<");
    expect(own).toContain("Edit details");
  });
});
