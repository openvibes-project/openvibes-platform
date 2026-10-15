// Who sees which menu entries: the access lists in registry.tsx, read the way the shell does.
import { describe, expect, it, vi } from "vitest";

// registry.tsx imports every view; nav.ts reads the location when loaded.
vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {} } });
});

import type { Permission, Session } from "../api/types";
import { views } from "./registry";
import { allows } from "./session";

const global = (permissions: Permission[]) =>
  ({ capabilities: permissions.map((permission) => ({ permission, scope: { kind: "global" } })) }) as unknown as Session;
const shows = (session: Session, label: string) =>
  views.find((v) => v.label === label)?.access.some((a) => allows(session, a)) === true;

describe("menu access", () => {
  it("an operator (rules.upload, no rules.read) sees Coverage and Settings", () => {
    const operator = global(["agents.read", "rules.upload", "rules.write", "tokens.read"]);
    expect(shows(operator, "Coverage")).toBe(true);
    expect(shows(operator, "Settings")).toBe(true);
  });
  it("a viewer without either rules permission does not see Coverage", () => {
    expect(shows(global(["agents.read"]), "Coverage")).toBe(false);
  });
});
