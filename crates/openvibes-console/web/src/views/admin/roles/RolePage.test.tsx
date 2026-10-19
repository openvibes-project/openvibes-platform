// The role page. Vitest runs in node with no DOM library (see ui/controls.test.tsx):
// the editor's state changes are a pure reducer, the page is checked as markup
// from react-dom/server, and the save goes through a stubbed fetch.
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { HostGroup, Role } from "../../../api/types";
import { SessionContext } from "../../../app/session";
import { ApiError } from "../../../api/client";
import { RoleBar } from "./RoleBar";
import { RoleEditor, refusal, saveRole } from "./RolePage";
import { type RoleState, blank, fromRole, reduce, saveBody } from "./roleState";

const groups: HostGroup[] = [
  { asset_group_id: "g-win", name: "WindowsServers", selectors: ["os=windows"], roles: 1 },
  { asset_group_id: "g-lin", name: "LinuxServers", selectors: ["os=linux"], roles: 0 },
];
/** Rendered for someone holding access.roles. */
const render = (role: Role | undefined, initial?: RoleState) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session: undefined, demo: false, can: () => true, canEverywhere: () => true }}>
    <RoleEditor role={role} groups={groups} {...(initial ? { initial } : {})} />
  </SessionContext.Provider>,
);
const page = (state: RoleState) => render(undefined, state);
/** The opening tag of the chip with this accessible name. */
const chip = (html: string, label: string) => new RegExp(`<button[^>]*aria-label="${label}"[^>]*>`).exec(html)?.[0] ?? "";
const run = (...actions: Parameters<typeof reduce>[1][]) => actions.reduce(reduce, blank());

afterEach(() => vi.unstubAllGlobals());

describe("role page", () => {
  it("starts blank with no hosts", () => {
    const html = page(blank());
    expect(html).not.toContain('aria-pressed="true"');
    expect(html).toContain("0 permissions · No hosts");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*title="Give it a name first"[^>]*>Create role<\/button>/);
  });

  it("picking Analyst fills the matrix and outlines the change", () => {
    const html = page(run({ type: "template", name: "Analyst" }));
    const triage = chip(html, "Triage alarms");
    expect(triage).toContain('aria-pressed="true"');
    expect(triage).toContain('data-changed="added"');
  });

  it("switching template outlines what it takes away", () => {
    const state = run({ type: "template", name: "Analyst" }, { type: "template", name: "Viewer" });
    expect(chip(page(state), "Triage alarms")).toContain('data-changed="removed"');
  });

  it("Assign cases brings View cases and says so", () => {
    const state = run({ type: "toggle", permission: "cases.assign" });
    expect([...state.on].sort()).toEqual(["cases.assign", "cases.read", "cases.write"]);
    const html = page(state);
    expect(chip(html, "Create and edit cases")).toContain('aria-pressed="true"');
    expect(chip(html, "View cases")).toContain('aria-pressed="true"');
    expect(html).toContain("Also turned on: Create and edit cases, View cases");
  });

  it("turning off View cases turns off Assign and says so", () => {
    const state = run({ type: "toggle", permission: "cases.assign" }, { type: "toggle", permission: "cases.read" });
    expect(state.on.size).toBe(0);
    expect(state.notice).toMatch(/^Also turned off: /);
    expect(state.notice).toContain("Assign cases");
    expect(state.notice).toContain("Create and edit cases");
  });

  it("a row's All turns the area on, and a column toggles it in every area", () => {
    expect(run({ type: "area", area: "Cases" }).on.size).toBe(3);
    const exports = run({ type: "column", column: "Export" });
    expect(exports.on.has("alarms.export") && exports.on.has("alarms.read")).toBe(true);
    expect(exports.notice).toContain("Also turned on: View alarms");
    expect(reduce(exports, { type: "column", column: "Export" }).on.has("alarms.export")).toBe(false);
  });

  it("platform permissions have the info mark", () => {
    const html = page(blank());
    const row = html.slice(html.indexOf("Rule sets"), html.indexOf("Site rules"));
    expect(row).toContain('title="Applies to the whole platform, whatever hosts the role reaches"');
    // Mixed area: the mark sits on the platform chip, not on the area.
    expect(chip(html, "Configure the assistant and internet lookups \\(platform-wide\\)")).toBeTruthy();
    expect(html).toContain('<span class="sr-only">(platform-wide)</span>');
    const assistant = html.slice(html.indexOf(">Assistant<"), html.indexOf(">Access<"));
    expect(assistant.match(/whatever hosts the role reaches/g)).toHaveLength(1);
  });

  it("All hosts replaces chosen groups", () => {
    const state = run({ type: "group", group: { asset_group_id: "g-win", name: "WindowsServers" } }, { type: "allHosts" });
    expect(state.reach).toEqual({ kind: "all" });
    const html = page(state);
    expect(html).toContain('aria-label="Remove All hosts"');
    expect(html).not.toContain('aria-label="Remove WindowsServers"');
    expect(html).toContain("0 permissions · All hosts");
  });

  it("no hosts says host permissions apply nowhere", () => {
    expect(page(blank())).toContain("apply nowhere");
  });

  it("Create sends the closed set and reach", async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ role_id: "r1" }), { status: 201 }));
    vi.stubGlobal("fetch", fetch);
    const state = run({ type: "name", name: " Night shift " }, { type: "toggle", permission: "cases.assign" },
      { type: "group", group: { asset_group_id: "g-win", name: "WindowsServers" } });
    expect(page(state)).toMatch(/<button[^>]*>Create role<\/button>/);
    expect(page(state)).not.toContain("Give it a name first");
    await saveRole("new", saveBody(state));
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/roles");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body.name).toBe("Night shift");
    expect([...(body.permissions as string[])].sort()).toEqual(["cases.assign", "cases.read", "cases.write"]);
    expect(body.reach).toEqual({ kind: "groups", asset_group_ids: ["g-win"] });
  });

  it("an edit sends the version with PATCH", async () => {
    const fetch = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetch);
    await saveRole("r1", { name: "x", permissions: [], reach: { kind: "none" }, version: 3 });
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/roles/r1");
    expect(init.method).toBe("PATCH");
    expect(JSON.parse(init.body as string)).toMatchObject({ version: 3 });
  });

  it("an existing role sends its version, a new one none", () => {
    const role: Role = { role_id: "r1", name: "Night shift", description: "", builtin: false, members: 0, version: 7, reach: { kind: "all" }, permissions: ["cases.read"] };
    expect(saveBody(fromRole(role), role).version).toBe(7);
    expect("version" in saveBody(blank())).toBe(false);
  });

  it("the outline legend names only what changed", () => {
    const html = page(run({ type: "template", name: "Viewer" }));
    expect(html).toContain("added");
    expect(html).not.toContain("taken away");
    expect(html).toContain("compared with your previous choice");
  });

  it("a refusal shows above the bar, and a stale save says so and reloads", () => {
    const html = renderToStaticMarkup(<RoleBar name="x" summary="0 permissions · No hosts" error="Name already taken" isNew={false} readOnly={false} busy={false} onCancel={() => {}} onSave={() => {}} onDelete={undefined} />);
    expect(html).toMatch(/role="alert"[^>]*>.*Name already taken/);
    expect(refusal(new ApiError(409, "stale_role", "stale"), "x")).toEqual({ message: "Someone else changed this role; your edits were not saved.", reload: true });
    expect(refusal(new ApiError(409, "role_name_taken", "A role named x exists"), "x")).toEqual({ message: "A role named x exists", reload: false });
  });

  it("Administrator is read-only", () => {
    const admin: Role = { role_id: "admin", name: "Administrator", description: "", builtin: true, members: 1, version: 1, reach: { kind: "all" }, permissions: ["alarms.read", "cases.read"] };
    const html = render(admin);
    expect(html).toContain("Administrator has every permission on all hosts and cannot be changed.");
    expect(html).not.toContain("Save role");
    expect(chip(html, "View alarms")).toContain("disabled");
    expect(/<input[^>]*aria-label="Name"[^>]*>/.exec(html)?.[0]).toContain("disabled");
  });
});
