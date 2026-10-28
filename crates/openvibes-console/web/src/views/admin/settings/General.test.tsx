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
import { type Send, createRowEditor } from "./rowEditor";

const settings: SettingsView = {
  items: [
    { key: "suppressions.require_approval", section: "Alarm suppressions", label: "Suppressions need approval", help: "A new suppression waits until someone else accepts it.", kind: "bool", applies: "live", default: false, value: true },
    { key: "sso.remove_inactive_days", section: "Single sign-on", label: "Remove inactive single sign-on users", help: "Days without a sign-in.", kind: "int", applies: "live", min: 1, max: 3650, default: 90, value: 90 },
    { key: "vulns.proxy_url", section: "Vulnerability feeds", label: "Proxy", help: "Where the feeds are fetched through.", kind: "text", applies: "live", default: "", value: "http://proxy.example:3128" },
    { key: "vulns.nvd_api_key", section: "Vulnerability feeds", label: "NVD API key", help: "Raises the rate limit.", kind: "secret", applies: "live", default: null, value: null, is_set: true },
    { key: "vulns.agent", section: "Vulnerability feeds", label: "Later", help: "Needs a restart.", kind: "int", applies: "restart", min: 1, max: 9, default: 1, value: 1 },
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

describe("General text and secret rows", () => {
  it("shows text as text, with a way back to the default when it was changed", () => {
    const out = html();
    expect(out).toMatch(/<input[^>]*type="text"[^>]*aria-label="Proxy"[^>]*value="http:\/\/proxy.example:3128"/);
    expect(out).toContain("Reset to default");
  });
  it("never shows a secret, only that it is set, and offers Remove", () => {
    const out = html();
    expect(out).toMatch(/<input[^>]*type="password"[^>]*aria-label="NVD API key"/);
    expect(out).toContain("Set. Type to replace");
    expect(out).toContain(">Remove<");
  });
  it("says which settings wait for a restart", () => {
    expect(html().match(/Applies after the service restarts/g)).toHaveLength(1);
  });
  it("sends a typed address as text, and null for a reset", async () => {
    const sent: unknown[] = [];
    const send: Send = async (_m, _p, body) => { sent.push(body); return {}; };
    const text = createRowEditor("vulns.proxy_url", "", send, () => {}, () => {}, "text");
    text.type(" http://p:1 ");
    await text.commit();
    await text.reset();
    expect(sent).toEqual([{ value: "http://p:1" }, { value: null }]);
  });
  it("ignores an emptied secret box and an unchanged address", async () => {
    const sent: unknown[] = [];
    const send: Send = async (_m, _p, body) => { sent.push(body); return {}; };
    const secret = createRowEditor("vulns.nvd_api_key", null, send, () => {}, () => {}, "secret");
    secret.type("  ");
    await secret.commit();
    const text = createRowEditor("vulns.proxy_url", "http://p:1", send, () => {}, () => {}, "text");
    text.type("http://p:1");
    await text.commit();
    expect(sent).toEqual([]);
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

describe("row editor", () => {
  const make = (value: unknown, send: Send) => {
    const calls: unknown[] = [];
    const ed = createRowEditor("sso.remove_inactive_days", value, async (m, p, b) => { calls.push(b); return send(m, p, b); }, () => {}, () => {});
    return { ed, calls };
  };
  const refuse = async () => { throw new ApiError(422, "invalid_setting", "t", [{ field: "value", code: "invalid", message: "Use a whole number from 1 to 3650" }]); };

  it("sends only a changed number", async () => {
    const { ed, calls } = make(90, async () => ({}));
    ed.type("90");
    await ed.commit();
    expect(calls).toEqual([]);
    expect(ed.state.text).toBeUndefined();
    ed.type("120");
    await ed.commit();
    expect(calls).toEqual([{ value: 120 }]);
    expect(ed.state.result).toEqual({ ok: true, message: "Saved · recorded in the audit log" });
  });
  it("Enter then the blur it causes saves once", async () => {
    const { ed, calls } = make(90, async () => ({}));
    ed.type("120");
    await Promise.all([ed.commit(), ed.commit()]);
    expect(calls).toHaveLength(1);
  });
  it("keeps the typed text when the server refuses", async () => {
    const { ed } = make(90, refuse);
    ed.type("0");
    await ed.commit();
    expect(ed.state).toMatchObject({ text: "0", busy: false, result: { ok: false, message: "Use a whole number from 1 to 3650" } });
  });
});
