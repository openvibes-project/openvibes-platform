// Markup only (vitest runs in node): a service account shows its roles by
// name, and the new-account picker offers only roles inside the creator's
// own access (the server refuses the rest).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import type { Capability, Session } from "../../api/types";
import { SessionContext } from "../../app/session";

// nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {} } });
});

const account = { service_account_id: "sa-1", name: "CI", enabled: true, active_tokens: 0, created_at: "2026-10-01T00:00:00Z", roles: [{ role_id: "admin", name: "Administrator" }, { role_id: "r_3f2a", name: "Lab readers" }] };
const role = (role_id: string, name: string, reach: unknown) => ({ role_id, name, description: "", builtin: false, members: 0, version: 1, permissions: ["hosts.read"], reach });
vi.mock("../../api/client", () => ({
  apiMessage: () => "", invalidate() {}, request: async () => ({}),
  useResource: (url: string | null) => ({ loading: false, data:
    url === "/api/v1/roles" ? [role("r_3f2a", "Lab readers", { kind: "groups", groups: [{ asset_group_id: "lab", name: "Lab" }] }), role("r_9b1c", "All readers", { kind: "all" })]
    : url === "/api/v1/service-accounts" ? { items: [account] } : { items: [] } }),
}));
// The picker's options, listed so the markup shows them.
vi.mock("../../ui/Select", () => ({
  Select: ({ options }: { options: { value: string; label: string }[] }) => <ul>{options.map((o) => <li key={o.value}>{o.label}</li>)}</ul>,
}));

import { ServiceAccountPanel } from "./ServiceAccountPanel";

const capabilities: Capability[] = [
  { permission: "service_accounts.read", scope: { kind: "global" } },
  { permission: "service_accounts.manage", scope: { kind: "global" } },
  { permission: "hosts.read", scope: { kind: "asset_groups", asset_group_ids: ["lab"] } },
];
const as = (node: React.ReactNode) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session: { capabilities } as unknown as Session, demo: false, can: () => true, canEverywhere: () => false }}>{node}</SessionContext.Provider>);

describe("service account roles", () => {
  // The list (Settings › Service accounts) is in the demo e2e (smoke.spec.ts).
  it("are shown by name on the account", () => {
    const html = as(<ServiceAccountPanel id="sa-1" />);
    expect(html).toContain("Administrator");
    expect(html).toContain("Lab readers");
    expect(html).not.toContain("r_3f2a");
  });
  it("offer only roles inside the creator's access", () => {
    const html = as(<ServiceAccountPanel id="new" />);
    expect(html).toContain("Lab readers");
    expect(html).not.toContain("All readers");
  });
});
