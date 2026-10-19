import { describe, expect, it } from "vitest";

import type { Capability } from "../api/types";
import { createDemoServer } from "./server";
import { resolveCapabilities, shareRefusal } from "./share";

type Server = ReturnType<typeof createDemoServer>;
const call = async <T = Record<string, unknown>>(server: Server, method: string, path: string, body?: unknown) => {
  const response = await server.handle(method, path, body);
  const text = await response.text();
  return { status: response.status, body: (text === "" ? {} : JSON.parse(text)) as T };
};
const role = (name: string, permissions: string[], reach: unknown = { kind: "all" }) => ({ name, description: "", permissions, reach });

describe("demo access rules (rbac.rs, share.rs)", () => {
  it("resolves roles like the server: Administrator everything, reaches unite, none grants no host permission", () => {
    const admin = resolveCapabilities([{ role_id: "admin", permissions: [], reach: { kind: "none" } }]);
    expect(admin).toHaveLength(48);
    expect(admin.every((c) => c.scope.kind === "global")).toBe(true);
    const caps = resolveCapabilities([
      { role_id: "a", permissions: ["hosts.read", "access.read"], reach: { kind: "groups", asset_group_ids: ["lab"] } },
      { role_id: "b", permissions: ["hosts.read"], reach: { kind: "groups", asset_group_ids: ["prod"] } },
      { role_id: "c", permissions: ["alarms.read"], reach: { kind: "none" } },
    ]);
    expect(caps).toEqual([
      { permission: "hosts.read", scope: { kind: "asset_groups", asset_group_ids: ["lab", "prod"] } },
      { permission: "access.read", scope: { kind: "global" } },
    ]);
  });

  it("refuses a role outside the share, naming the permission in console words", () => {
    const editor: Capability[] = [{ permission: "hosts.read", scope: { kind: "asset_groups", asset_group_ids: ["lab"] } }, { permission: "audit.read", scope: { kind: "global" } }];
    const lab = { kind: "groups" as const, groups: [{ asset_group_id: "lab", name: "Lab" }] };
    expect(shareRefusal(editor, ["hosts.read", "audit.read"], lab)).toBeNull();
    expect(shareRefusal(editor, ["hosts.read"], { kind: "all" })).toContain("View hosts is outside it");
    expect(shareRefusal(editor, ["hosts.revoke"], lab)).toBe("You can only give roles that fit inside your own access (Revoke a host is outside it)");
  });

  it("gives the scoped operator production hosts only", async () => {
    const hosts = (await call<{ items: { hostname: string }[] }>(createDemoServer({ persona: "scoped_operator" }), "GET", "/api/v1/agents?limit=100")).body.items;
    expect(hosts.length).toBeGreaterThan(0);
    expect(hosts.every((h) => h.hostname.includes(".prod."))).toBe(true);
  });
});

describe("demo roles API", () => {
  it("lists every role for access.read, and anyone's own roles with held=true", async () => {
    const viewer = createDemoServer({ persona: "viewer" });
    expect((await call(viewer, "GET", "/api/v1/roles")).status).toBe(403);
    const held = await call<{ role_id: string; name: string }[]>(viewer, "GET", "/api/v1/roles?held=true");
    expect(held.body.map((r) => r.name)).toEqual(["Viewer"]);
    expect((await call<unknown[]>(createDemoServer({ persona: "admin" }), "GET", "/api/v1/roles")).body.length).toBeGreaterThan(1);
  });

  it("checks a token's account before its Idempotency-Key, as the server does", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await call(server, "POST", "/api/v1/service-accounts/sa-nope/tokens", { label: "x", expires_in_hours: 24 })).status).toBe(404);
  });

  it("answers service accounts with their roles' names", async () => {
    const server = createDemoServer({ persona: "admin" });
    const accounts = await call<{ items: { name: string; roles: { role_id: string; name: string }[] }[] }>(server, "GET", "/api/v1/service-accounts");
    expect(accounts.body.items.find((a) => a.name === "CI rule publisher")?.roles).toEqual([{ role_id: "role-opprod", name: "Operator (Prod)" }]);
    const made = await call<{ roles: unknown }>(server, "POST", "/api/v1/service-accounts", { name: "Backup", role_ids: ["admin"] });
    expect(made.body.roles).toEqual([{ role_id: "admin", name: "Administrator" }]);
  });

  it("creates, edits and deletes with the server's refusals", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await call(server, "POST", "/api/v1/roles", role("WINDOWS lead", ["hosts.read"]))).body.code).toBe("role_name_taken");
    expect((await call(server, "POST", "/api/v1/roles", role("x", ["hosts.label"]))).body).toMatchObject({ code: "missing_needs", permission: "hosts.label", needs: "hosts.read" });
    expect((await call(server, "POST", "/api/v1/roles", role("x", [], { kind: "groups", asset_group_ids: ["grp-nope"] }))).body.code).toBe("unknown_group");
    expect((await call(server, "PATCH", "/api/v1/roles/admin", { ...role("x", []), version: 1 })).body.code).toBe("protected_role");
    const made = await call<{ role_id: string; version: number; reach: unknown }>(server, "POST", "/api/v1/roles", role("Night", ["hosts.read"], { kind: "groups", asset_group_ids: ["grp-win"] }));
    expect(made.status).toBe(201);
    expect(made.body.reach).toEqual({ kind: "groups", groups: [{ asset_group_id: "grp-win", name: "WindowsServers" }] });
    const path = `/api/v1/roles/${made.body.role_id}`;
    expect((await call(server, "PATCH", path, role("Night", []))).body.code).toBe("invalid_role");
    expect((await call(server, "PATCH", path, { ...role("Night", []), version: 1 })).status).toBe(200);
    expect((await call(server, "PATCH", path, { ...role("Night", []), version: 1 })).body.code).toBe("stale_role");
    expect((await call(server, "PUT", `/api/v1/users/u-vic/roles/${made.body.role_id}`)).status).toBe(204);
    expect((await call(server, "DELETE", path)).body).toMatchObject({ code: "role_in_use", holders: 1 });
    expect((await call(server, "DELETE", `/api/v1/users/u-vic/roles/${made.body.role_id}`)).status).toBe(204);
    expect((await call(server, "DELETE", path)).status).toBe(204);
  });
});

describe("demo people API", () => {
  it("shows a person's access grouped by where it applies and their recent activity", async () => {
    const person = (await call<{ access: { permission: string; applies: string; groups: unknown[] }[]; recent: { action: string }[] }>(
      createDemoServer({ persona: "admin" }), "GET", "/api/v1/users/u-wen")).body;
    expect(person.access.find((a) => a.permission === "alarms.triage")).toMatchObject({ applies: "groups", groups: [{ asset_group_id: "grp-win", name: "WindowsServers" }] });
    expect(person.access.find((a) => a.permission === "access.grant")).toMatchObject({ applies: "platform" });
    expect(person.recent.length).toBe(10);
  });

  it("refuses changes to yourself and keeps the last Administrator", async () => {
    const server = createDemoServer({ persona: "admin" });
    expect((await call(server, "POST", "/api/v1/users/u-admin/disable")).body.code).toBe("permission_denied");
    expect((await call(server, "POST", "/api/v1/users/u-admin/reset-password")).body.code).toBe("use_change_password");
    expect((await call(server, "DELETE", "/api/v1/users/u-admin/roles/admin")).body.title).toBe("Nobody can change their own roles");
    expect((await call(server, "PUT", "/api/v1/users/u-sam/roles/admin")).status).toBe(204);
    expect((await call(server, "POST", "/api/v1/users/u-sam/disable")).status).toBe(204);
    // Sam is disabled, so Alex is the last enabled Administrator; Sam's Administrator may go.
    expect((await call(server, "DELETE", "/api/v1/users/u-sam/roles/admin")).status).toBe(204);
    expect((await call(server, "GET", "/api/v1/users/u-sam")).body.enabled).toBe(false);
  });

  it("lets anyone read their own page, and nobody else's without access.read", async () => {
    const viewer = createDemoServer({ persona: "viewer" });
    expect((await call(viewer, "GET", "/api/v1/users/u-vic")).status).toBe(200);
    expect((await call(viewer, "GET", "/api/v1/users/u-sam")).status).toBe(403);
  });

  it("assigns triage only to people who may triage the area on some host, or an Administrator", async () => {
    const server = createDemoServer({ persona: "admin" });
    const alarm = (await call<{ items: { id: string }[] }>(server, "GET", "/api/v1/alarms")).body.items[0];
    const triage = (assigned_to: string) => call(server, "POST", "/api/v1/alarms/bulk", { action: "assign", items: [{ id: alarm?.id }], assignee: assigned_to });
    expect((await triage("vic")).body).toMatchObject({ changed: 0, skipped: [{ reason: "assignee unavailable" }] });
    expect((await triage("wen")).body).toMatchObject({ changed: 1 });
  });
});
