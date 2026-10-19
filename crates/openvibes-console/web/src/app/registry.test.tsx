// Who sees which menu entries: the access lists in registry.tsx, read the way the shell does.
import { describe, expect, it, vi } from "vitest";

// registry.tsx imports every view; nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {} } });
});

import type { Permission, Session } from "../api/types";
import { views } from "./registry";
import { allows } from "./session";

const held = (permissions: Permission[]) =>
  ({ capabilities: permissions.map((permission) => ({ permission, scope: { kind: "global" } })) }) as unknown as Session;
const shows = (session: Session, label: string) =>
  views.find((v) => v.label === label)?.access.some((a) => allows(session, a)) === true;

describe("menu access", () => {
  it("an operator (rules.publish with its views) sees Coverage and Settings", () => {
    const operator = held(["hosts.read", "rules.publish", "rules.read", "rules.coverage.read", "site_rules.read", "tokens.read"]);
    expect(shows(operator, "Coverage")).toBe(true);
    expect(shows(operator, "Settings")).toBe(true);
  });
  it("Settings opens for /settings/… sub-pages, and for host_groups.manage alone", () => {
    expect(views.find((v) => v.label === "Settings")?.prefix).toBe("/settings/");
    expect(shows(held(["host_groups.manage"]), "Settings")).toBe(true);
  });
  it("a viewer without rules.coverage.read does not see Coverage", () => {
    expect(shows(held(["hosts.read"]), "Coverage")).toBe(false);
  });
});
