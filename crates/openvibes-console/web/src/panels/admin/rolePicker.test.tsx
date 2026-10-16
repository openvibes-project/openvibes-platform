// Markup only (vitest runs in node): a new user or service account has no
// role until one is chosen, so nobody becomes Administrator by default.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {} } });
});

// The live role list, as GET /api/v1/access-control answers on a fresh install plus one role.
vi.mock("../../api/client", () => ({
  apiMessage: () => "", invalidate() {}, request: async () => ({}),
  useResource: () => ({ loading: false, data: { roles: [
    { role_id: "admin", display_name: "Administrator", builtin: true, permissions: [] },
    { role_id: "r_1", display_name: "Night shift", builtin: false, permissions: [] },
  ] } }),
}));

import { ServiceAccountPanel } from "./ServiceAccountPanel";
import { NewUser } from "./UserPanel";

const submit = (html: string, label: string) => html.match(new RegExp(`<button[^>]*type="submit"[^>]*>(?:(?!</button>).)*${label}`))?.[0] ?? "";

describe("role pickers", () => {
  it("a new user starts with no role and cannot be created until one is chosen", () => {
    const html = renderToStaticMarkup(<NewUser />);
    expect(html).toContain("Choose a role…");
    expect(html).not.toContain("Administrator");
    expect(submit(html, "Create user")).toContain('disabled=""');
  });
  it("a new service account starts with no role and cannot be created until one is chosen", () => {
    const html = renderToStaticMarkup(<ServiceAccountPanel id="new" />);
    expect(html).toContain("Choose a role…");
    expect(html).not.toContain("Administrator");
    expect(submit(html, "Create account")).toContain('disabled=""');
  });
});
