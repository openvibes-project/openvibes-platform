// The suppress form (approved screen 12) as markup, its where choices and
// its POST body as pure functions.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { AlarmSuppressionOptions } from "../../api/types";
import { type SuppressFields, SuppressForm, bodyOf, whereChoices } from "./SuppressForm";

const source = { id: "9001", host: "web-01.example.test", exe: "/usr/bin/sh", args: ["sh", "-c", "/usr/local/bin/healthcheck"] };
const options = (more: Partial<AlarmSuppressionOptions> = {}): AlarmSuppressionOptions =>
  ({ require_approval: false, all_hosts: false, groups: [{ id: "g-web", name: "Web" }, { id: "g-prod", name: "Production" }], ...more });
const html = (opts = options(), initial: Partial<SuppressFields> = {}) =>
  renderToStaticMarkup(<SuppressForm source={source} options={opts} initial={initial} onClose={() => undefined} />);

describe("SuppressForm", () => {
  it("offers this program (its exe) or this exact command (exe and args)", () => {
    const out = html();
    expect(out).toContain("This program");
    expect(out).toContain("This exact command");
    expect(out).toContain("/usr/bin/sh");
    expect(html(options(), { what: "command" })).toContain("/usr/bin/sh sh -c /usr/local/bin/healthcheck");
  });
  it("offers this host, each group, then all hosts only when allowed", () => {
    expect(whereChoices(source, options()).map((c) => c.label)).toEqual(["This host (web-01.example.test)", "Web", "Production"]);
    expect(whereChoices(source, options({ all_hosts: true })).map((c) => c.label)).toEqual(["This host (web-01.example.test)", "Web", "Production", "All hosts"]);
  });
  it("offers 7 days, 30 days or until removed", () => {
    const out = html();
    for (const label of ["7 days", "30 days", "Until removed"]) expect(out).toContain(`>${label}</button>`);
  });
  it("keeps the button disabled until a reason is given", () => {
    expect(html()).toMatch(/<button[^>]*type="submit"[^>]*disabled=""[^>]*>Suppress<\/button>/);
    expect(html(options(), { reason: "health check" })).not.toMatch(/<button[^>]*type="submit"[^>]*disabled/);
  });
  it("says a request waits when approval is on, and asks to Request", () => {
    const on = html(options({ require_approval: true }), { reason: "x" });
    expect(on).toContain("Someone who can approve on those hosts must accept it. Until then these alarms keep arriving.");
    expect(on).toMatch(/type="submit"[^>]*>Request<\/button>/);
    const off = html(options(), { reason: "x" });
    expect(off).not.toContain("Someone who can approve");
    expect(off).toMatch(/type="submit"[^>]*>Suppress<\/button>/);
  });
});

describe("bodyOf", () => {
  it("gives the exact POST body", () => {
    expect(bodyOf("9001", { what: "program", where: "host", forDays: 7, reason: "  health check " }))
      .toEqual({ alarm_id: "9001", what: "program", where: { kind: "host" }, for_days: 7, reason: "health check" });
    expect(bodyOf("9001", { what: "command", where: "group:g-web", forDays: null, reason: "x" }))
      .toEqual({ alarm_id: "9001", what: "command", where: { kind: "group", group_id: "g-web" }, for_days: null, reason: "x" });
    expect(bodyOf("9001", { what: "program", where: "all", forDays: 30, reason: "x" }).where).toEqual({ kind: "all" });
  });
});
