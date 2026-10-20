// Settings › General (approved screen 11) as markup, and its save as a pure function.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import { ApiError } from "../../../api/client";
import type { Role, SettingsView } from "../../../api/types";
import { SessionContext } from "../../../app/session";
import { GeneralBody, saveValue } from "./General";

const settings: SettingsView = {
  items: [
    { key: "suppressions.require_approval", section: "Alarm suppressions", label: "Suppressions need approval", help: "A new suppression waits until someone else accepts it.", kind: "bool", default: false, value: true },
    { key: "sso.remove_inactive_days", section: "Single sign-on", label: "Remove inactive single sign-on users", help: "Days without a sign-in.", kind: "int", min: 1, max: 3650, default: 90, value: 90 },
  ],
  recent: [{ at: "2026-10-16T09:00:00Z", actor: "alex", key: "suppressions.require_approval", old: null, new: true }],
};
const role = (name: string, permissions: string[]) => ({ role_id: name, name, permissions }) as unknown as Role;
const html = (roles: Role[] = []) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session: undefined, demo: false, can: () => true, canEverywhere: () => true }}><GeneralBody settings={settings} roles={roles} /></SessionContext.Provider>,
);

describe("General", () => {
  it("lists the sections with their counts", () => {
    const out = html();
    expect(out).toContain("On this page");
    expect(out).toMatch(/Alarm suppressions<\/a><span[^>]*>1</);
    expect(out).toMatch(/Single sign-on<\/a><span[^>]*>1</);
  });
  it("names the controls and shows the help", () => {
    const out = html();
    expect(out).toContain('aria-label="Suppressions need approval"');
    expect(out).toMatch(/<input[^>]*aria-label="Remove inactive single sign-on users"[^>]*>/);
    expect(out).toMatch(/min="1"/);
    expect(out).toMatch(/max="3650"/);
    expect(out).toContain("A new suppression waits until someone else accepts it.");
  });
  it("names who can approve, or says no role does", () => {
    expect(html([role("Lead", ["alarms.suppressions.approve"]), role("Viewer", [])])).toContain("Approvers: people whose role holds Approve suppressions on those hosts — Lead");
    expect(html([role("Viewer", [])])).toContain("no role holds it yet");
  });
  it("shows recent changes with a link to the audit log", () => {
    const out = html();
    expect(out).toContain("Changed a setting");
    expect(out).toContain("/audit?q=settings.changed");
  });
});

describe("saveValue", () => {
  it("reports success", async () => {
    expect(await saveValue("k", 5, async () => ({}))).toEqual({ ok: true, message: "Saved · recorded in the audit log" });
  });
  it("turns a 422 into the server's field message", async () => {
    const refuse = async () => { throw new ApiError(422, "invalid_setting", "The setting value is invalid", [{ field: "value", code: "invalid", message: "Use a whole number from 1 to 3650" }]); };
    expect(await saveValue("k", 0, refuse)).toEqual({ ok: false, message: "Use a whole number from 1 to 3650" });
  });
});
