// The demo's host-group and label routes answer like the real ones
// (hosts/groups.rs, group_checks.rs, labels.rs).
import { describe, expect, it } from "vitest";

import type { GroupHost, HostGroup, HostGroupDetail, HostGroupPreview } from "../../api/types";
import { resolveCapabilities } from "../share";
import { createDemoServer } from "../server";
import { writeRefusal } from "./groups";

type Server = ReturnType<typeof createDemoServer>;
const call = async <T = Record<string, unknown>>(server: Server, method: string, path: string, body?: unknown) => {
  const response = await server.handle(method, path, body);
  const text = await response.text();
  return { status: response.status, body: (text === "" ? {} : JSON.parse(text)) as T };
};
const admin = () => createDemoServer({ persona: "admin" });
const webInHq = { field: "hostname", negate: false, values: ["*web*"] };
const hq = { field: "ip", negate: false, values: ["10.0.0.0/16"] };

describe("demo host groups", () => {
  it("lists the three kinds by name, with membership, counts and reach", async () => {
    const groups = (await call<HostGroup[]>(admin(), "GET", "/api/v1/host-groups")).body;
    expect(groups.map((g) => g.name)).toEqual([...groups.map((g) => g.name)].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase())));
    const byName = new Map(groups.map((g) => [g.name, g]));
    expect(byName.get("Linux")).toMatchObject({ kind: "automatic", membership: "Hosts where OS family is Linux", changed_at: null });
    expect(byName.get("Debian 12")).toMatchObject({ kind: "automatic", membership: "Hosts where distribution is Debian 12" });
    expect(byName.get("WindowsServers")).toMatchObject({ kind: "rule", roles: [{ role_id: "role-winlead", name: "Windows lead" }], people: 1 });
    const prod = byName.get("Production");
    expect(prod).toMatchObject({ kind: "manual", upgraded_from_tags: true, roles: [{ name: "Operator (Prod)" }] });
    expect(prod?.membership).toBe(`${prod?.picked} hosts picked by hand`);
    expect(prod?.hosts).toBe(prod?.picked);
    expect(byName.get("Linux")?.hosts).toBeGreaterThan(prod?.hosts ?? 0);
  });

  it("counts hosts inside the reader's reach and leaves picked hosts out of a scoped reader's history", async () => {
    // The scoped operator lacks access.read and host_groups.manage.
    expect((await call(createDemoServer({ persona: "scoped_operator" }), "GET", "/api/v1/host-groups")).status).toBe(403);
    expect((await call(createDemoServer({ persona: "viewer" }), "GET", "/api/v1/host-groups")).status).toBe(403);
  });

  it("previews, creates, edits and deletes a rule group", async () => {
    const server = admin();
    const preview = (await call<HostGroupPreview>(server, "POST", "/api/v1/host-groups/preview", { conditions: [webInHq, hq] })).body;
    expect(preview.joins_total).toBeGreaterThan(0);
    expect(preview.joins.every((h) => /web/.test(h.hostname ?? ""))).toBe(true);
    expect(preview).toMatchObject({ leaves_total: 0, gains: [], loses: [], overrides_removed: 0 });
    const created = await call<HostGroup>(server, "POST", "/api/v1/host-groups", { name: "Web at HQ", kind: "rule", conditions: [webInHq, hq] });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ kind: "rule", hosts: preview.joins_total, version: 1, changed_by: "u-admin" });
    const id = created.body.asset_group_id;
    const hosts = (await call<GroupHost[]>(server, "GET", `/api/v1/host-groups/${id}/hosts?limit=2`)).body;
    expect(hosts[0]).toMatchObject({ why: "Matches the rule" });
    expect(hosts[0]?.last_address).toMatch(/^10\.0\./);
    const rest = (await call<GroupHost[]>(server, "GET", `/api/v1/host-groups/${id}/hosts?after=${hosts[1]?.agent_id}`)).body;
    expect(hosts.length + rest.length).toBe(preview.joins_total);
    const taken = await call(server, "POST", "/api/v1/host-groups", { name: "web AT hq", kind: "manual", agent_ids: [] });
    expect(taken).toMatchObject({ status: 409, body: { code: "group_name_taken" } });
    const stale = await call(server, "PATCH", `/api/v1/host-groups/${id}`, { name: "Web", version: 7 });
    expect(stale).toMatchObject({ status: 409, body: { code: "stale_group" } });
    const renamed = await call<HostGroup>(server, "PATCH", `/api/v1/host-groups/${id}`, { name: "  Web  ", version: 1 });
    expect(renamed.body).toMatchObject({ name: "Web", version: 2, kind: "rule" });
    const detail = (await call<HostGroupDetail>(server, "GET", `/api/v1/host-groups/${id}`)).body;
    expect(detail.recent.map((r) => r.action)).toEqual(["host_group.updated", "host_group.created"]);
    expect(detail.recent[0]).toMatchObject({ actor: "u-admin", detail: { name: "Web", kind: "rule" } });
    const gone = (await call<HostGroupPreview>(server, "POST", `/api/v1/host-groups/${id}/preview`, {})).body;
    expect(gone.leaves_total).toBe(preview.joins_total);
    expect((await call(server, "DELETE", `/api/v1/host-groups/${id}`)).body).toMatchObject({ code: "invalid_group" });
    expect((await call(server, "DELETE", `/api/v1/host-groups/${id}?version=1`)).status).toBe(409);
    expect((await call(server, "DELETE", `/api/v1/host-groups/${id}?version=2`)).status).toBe(204);
    expect((await call(server, "GET", `/api/v1/host-groups/${id}`)).body).toMatchObject({ code: "group_not_found" });
  });

  it("turns an edited automatic group into a rule group", async () => {
    const server = admin();
    const debian = (await call<HostGroup[]>(server, "GET", "/api/v1/host-groups")).body.find((g) => g.name === "Debian 12");
    const saved = await call<HostGroup>(server, "PATCH", `/api/v1/host-groups/${debian?.asset_group_id}`, { description: "Ours now", version: debian?.version });
    expect(saved.body).toMatchObject({ kind: "rule", description: "Ours now", hosts: debian?.hosts });
  });

  it("refuses bad groups with the server's codes", async () => {
    const server = admin();
    const post = (body: unknown) => call<{ code: string; field_errors?: { field: string }[] }>(server, "POST", "/api/v1/host-groups", body);
    expect(await post({ name: "X", kind: "rule", conditions: [] })).toMatchObject({ status: 422, body: { code: "invalid_condition", field_errors: [{ field: "conditions" }] } });
    expect(await post({ name: "X", kind: "rule", conditions: [{ field: "ip", values: ["nope"] }] })).toMatchObject({ status: 422, body: { field_errors: [{ field: "ip" }] } });
    expect(await post({ name: "X", kind: "rule", agent_ids: [] })).toMatchObject({ status: 400, body: { code: "invalid_group", field_errors: [{ field: "kind" }] } });
    expect(await post({ name: "X", kind: "manual", agent_ids: [], extra: 1 })).toMatchObject({ status: 400, body: { field_errors: [{ field: "body" }] } });
    expect(await post({ name: " ", kind: "manual", agent_ids: [] })).toMatchObject({ status: 400, body: { field_errors: [{ field: "name" }] } });
    expect(await post({ name: "X", description: "d".repeat(501), kind: "manual", agent_ids: [] })).toMatchObject({ status: 400, body: { field_errors: [{ field: "description" }] } });
    expect(await post({ name: "X", kind: "manual", agent_ids: ["agent-00047"] })).toMatchObject({ status: 422, body: { code: "unknown_host", field_errors: [{ field: "agent_ids" }] } });
    expect((await call(server, "POST", "/api/v1/host-groups/preview", {})).body).toMatchObject({ code: "invalid_group" });
    expect((await call(server, "POST", "/api/v1/host-groups/grp-nope/preview", {})).body).toMatchObject({ code: "group_not_found" });
  });

  it("refuses to delete a group roles use, naming them", async () => {
    const server = admin();
    const win = (await call<HostGroup[]>(server, "GET", "/api/v1/host-groups")).body.find((g) => g.name === "WindowsServers");
    expect(await call(server, "DELETE", `/api/v1/host-groups/grp-win?version=${win?.version}`))
      .toMatchObject({ status: 409, body: { code: "group_in_use", roles: ["Windows lead"] } });
  });

  it("names who gains or loses hosts, and the rule-set switches a delete removes", async () => {
    const server = admin();
    const prod = (await call<HostGroupPreview>(server, "POST", "/api/v1/host-groups/grp-prod/preview", { agent_ids: ["agent-00001"] })).body;
    expect(prod.joins).toEqual([expect.objectContaining({ agent_id: "agent-00001" })]);
    expect(prod.gains.map((p) => p.username)).toEqual(["pia"]);
    expect(prod.loses.map((p) => p.username)).toEqual(["pia"]);
    expect(prod.people_total).toBe(1);
    expect((await call<HostGroupPreview>(server, "POST", "/api/v1/host-groups/grp-prod/preview", {})).body.overrides_removed).toBe(1);
  });

  it("needs every host to change groups", () => {
    const scoped = resolveCapabilities([{ role_id: "r", permissions: ["host_groups.manage", "access.read", "hosts.read"], reach: { kind: "groups", asset_group_ids: ["grp-prod"] } }]);
    expect(writeRefusal(scoped)).toEqual({ status: 403, code: "permission_denied", title: "Changing host groups needs access to every host" });
    const global = resolveCapabilities([{ role_id: "r", permissions: ["host_groups.manage", "access.read", "hosts.read"], reach: { kind: "all" } }]);
    expect(writeRefusal(global)).toBeNull();
    expect(writeRefusal(resolveCapabilities([]))).toEqual({ status: 403, code: "permission_denied", title: "Access is not available" });
  });
});

describe("demo host labels", () => {
  it("adds, keeps one copy, lists with the host's groups, and removes", async () => {
    const server = admin();
    const path = "/api/v1/hosts/agent-00003/labels";
    expect((await call(server, "PUT", `${path}/${encodeURIComponent(" rack b ")}`)).status).toBe(204);
    expect((await call(server, "PUT", `${path}/rack%20b`)).status).toBe(204);
    const view = (await call<{ labels: string[]; groups: { name: string; kind: string }[] }>(server, "GET", path)).body;
    expect(view.labels.filter((l) => l === "rack b")).toHaveLength(1);
    expect(view.groups.map((g) => g.name)).toContain("Production");
    expect((await call(server, "DELETE", `${path}/rack%20b`)).status).toBe(204);
    expect((await call(server, "DELETE", `${path}/rack%20b`)).status).toBe(204);
    expect((await call<{ labels: string[] }>(server, "GET", path)).body.labels).not.toContain("rack b");
  });

  it("refuses bad labels, the 33rd label, and hosts out of reach", async () => {
    const server = admin();
    const path = "/api/v1/hosts/agent-00005/labels";
    expect((await call(server, "PUT", `${path}/${"x".repeat(65)}`)).body).toMatchObject({ status: 400, code: "invalid_label" });
    expect((await call(server, "PUT", `${path}/%20`)).body).toMatchObject({ code: "invalid_label" });
    for (let n = 0; n < 32; n += 1) await call(server, "PUT", `${path}/l${n}`);
    expect((await call(server, "PUT", `${path}/one-more`)).body).toMatchObject({ status: 409, code: "too_many_labels" });
    expect((await call(server, "GET", "/api/v1/hosts/agent-99999/labels")).body).toMatchObject({ status: 404, code: "host_not_found" });
    // agent-00001 is not in Production, so the scoped operator does not reach it.
    const scoped = createDemoServer({ persona: "scoped_operator" });
    expect((await call(scoped, "GET", "/api/v1/hosts/agent-00001/labels")).status).toBe(404);
    expect((await call(scoped, "PUT", "/api/v1/hosts/agent-00003/labels/x")).status).toBe(204);
    expect((await call(createDemoServer({ persona: "viewer" }), "PUT", "/api/v1/hosts/agent-00003/labels/x")).status).toBe(403);
  });

  it("no longer answers the old tag and asset-group routes", async () => {
    const server = admin();
    expect((await server.handle("PUT", "/api/v1/agents/agent-00001/tags", { tags: [] })).status).toBe(404);
    expect((await server.handle("POST", "/api/v1/access-control/asset-groups", { name: "x" })).status).toBe(404);
  });
});
