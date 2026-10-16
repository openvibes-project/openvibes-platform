// Settings › People as markup (vitest runs in node, no DOM library).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/settings", search: "?tab=people" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

vi.mock("../../../api/client", () => ({
  apiMessage: () => "", invalidate() {}, request: async () => ({}),
  useResource: () => ({ loading: false, data: [
    { user_id: "u-wendy", username: "wendy", display_name: "Wendy Ward", enabled: true, auth_source: "password", last_sign_in_at: null, roles: [
      { role_id: "r-win", name: "Windows lead", builtin: false, permissions: [], reach: { kind: "groups", groups: [{ asset_group_id: "g-win", name: "WindowsServers" }] } },
      { role_id: "r-view", name: "Viewer", builtin: false, permissions: [], reach: { kind: "all" } },
    ] },
    { user_id: "u-sam", username: "sam", display_name: "Sam Analyst", enabled: false, auth_source: "sso", last_sign_in_at: null, roles: [] },
  ] }),
}));

// useLocation is a client-only store: the list's URL state, fixed.
vi.mock("../../../app/nav", () => ({
  nav: { view() {}, href: () => "#", setParams() {}, open() {} },
  useLocation: () => ({ view: "/settings", params: new URLSearchParams("tab=people"), panels: [] }),
  useTopPanel: () => undefined,
}));

import { People } from "./People";

describe("people list", () => {
  it("badges show where each role applies", () => {
    const html = renderToStaticMarkup(<People />);
    expect(html).toMatch(/Windows lead<span[^>]*> · WindowsServers<\/span>/);
    expect(html).toMatch(/Viewer<span[^>]*> · All hosts<\/span>/);
    expect(html).toContain("Single sign-on");
    expect(html).toContain("Disabled");
    expect(html).toContain("No roles");
  });
});
