// Markup only (vitest runs in node): a new user or service account has no
// role until one is chosen, so nobody becomes Administrator by default.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {} } });
});

// The live role list, as GET /api/v1/roles answers on a fresh install plus one role.
vi.mock("../../api/client", () => ({
  apiMessage: () => "", invalidate() {}, request: async () => ({}),
  useResource: () => ({ loading: false, data: [
    { role_id: "admin", name: "Administrator", builtin: true, permissions: [], reach: { kind: "all" } },
    { role_id: "r_1", name: "Night shift", builtin: false, permissions: [], reach: { kind: "all" } },
  ] }),
}));

import { ServiceAccountPanel } from "./ServiceAccountPanel";
import { NewPersonDialog } from "../../views/admin/people/NewPersonDialog";

const submit = (html: string, label: string) => html.match(new RegExp(`<button[^>]*type="submit"[^>]*>(?:(?!</button>).)*${label}`))?.[0] ?? "";

describe("role pickers", () => {
  it("a new person starts with no role and cannot be created until one is chosen", () => {
    const html = renderToStaticMarkup(<NewPersonDialog onClose={() => {}} />);
    expect(html).toContain("Choose a role…");
    expect(html).not.toContain("Administrator");
    expect(submit(html, "Create person")).toContain('disabled=""');
  });
  it("a new service account starts with no role and cannot be created until one is chosen", () => {
    const html = renderToStaticMarkup(<ServiceAccountPanel id="new" />);
    expect(html).toContain("Choose a role…");
    expect(html).not.toContain("Administrator");
    expect(submit(html, "Create account")).toContain('disabled=""');
  });
});
