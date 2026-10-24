// Spec §15: two teams, each seeing and changing only its own hosts; a team
// lead gives only roles inside their own access. console-e2e-server.sh
// seeds linux-1/2 and windows-1/2 (each team's rule group matches its
// hostnames), each with one `e2e.team_host` finding and one alarm. The
// browsers share one server, so every name carries the project's.
import { type Page, expect, test } from "@playwright/test";

import templates from "../../src/api/templates.json" with { type: "json" };
import { api, firstSignIn, openFirstFinding, signIn } from "./helpers";

const ANALYST = templates.find((t) => t.name === "Analyst")?.permissions ?? [];
const agentOf: Record<string, string> = {
  "linux-1": "agent.00000000-0000-4000-8000-000000000001",
  "windows-1": "agent.00000000-0000-4000-8000-000000000003",
};

/** A rule group "hostname matches `<prefix>-*`", made by the signed-in Administrator. */
async function group(page: Page, name: string, prefix: string) {
  const created = await api(page, "POST", "/api/v1/host-groups", {
    name, kind: "rule", conditions: [{ field: "hostname", negate: false, values: [`${prefix}-*`] }],
  });
  expect(created.status).toBe(201);
  return (created.json as { asset_group_id: string }).asset_group_id;
}

async function person(page: Page, username: string, roleId: string) {
  const created = await api(page, "POST", "/api/v1/users", { username, display_name: `${username} person`, role_ids: [roleId] });
  expect(created.status).toBe(201);
  return created.json as { user_id: string; one_time_password: string };
}

/** Mitigates `e2e.team_host` on one host through the bulk API, as `page`'s person. */
const mitigate = (page: Page, host: string) => api(page, "POST", "/api/v1/compliance/bulk", {
  action: "state", state: "mitigated", note: "e2e team check",
  items: [{ rule_set_id: "e2e", rule_id: "e2e.team_host", agent_id: agentOf[host] }],
});

const triageState = async (page: Page, host: string) =>
  ((await api(page, "GET", `/api/v1/compliance/latest/${agentOf[host]}/e2e/e2e.team_host/triage`)).json as { state: string }).state;

test("two teams each see and change only their hosts, and a team lead gives only roles inside their access", async ({ page, browser }, info) => {
  const tag = `${info.project.name}-${Date.now().toString(36)}`;
  await signIn(page, "alex");
  const groups = { linux: await group(page, `linux ${tag}`, "linux"), windows: await group(page, `windows ${tag}`, "windows") };

  // 1. Two roles from the Analyst template, each on its group, on the role page.
  const roleIds: Record<string, string> = {};
  for (const [os, team] of [["linux", "Linux team"], ["windows", "Windows team"]] as const) {
    await page.goto("/settings/roles/new");
    await page.getByRole("textbox", { name: "Name" }).fill(`${team} ${tag}`);
    await page.getByRole("combobox", { name: "Start from" }).click();
    await page.getByRole("option", { name: /^Analyst template/ }).click();
    await page.getByRole("searchbox", { name: "Search host groups" }).click();
    await page.getByRole("group", { name: "Host groups" }).getByRole("button", { name: `${os} ${tag}` }).click();
    await page.getByRole("button", { name: "Create role" }).click();
    await expect(page.locator(".toast").last()).toContainText("Role created");
    const roles = (await api(page, "GET", "/api/v1/roles")).json as { role_id: string; name: string }[];
    roleIds[os] = roles.find((r) => r.name === `${team} ${tag}`)?.role_id ?? "";
    expect(roleIds[os]).not.toBe("");
  }
  const people = { linux: await person(page, `linux-${tag}`, roleIds.linux ?? ""), windows: await person(page, `windows-${tag}`, roleIds.windows ?? "") };

  const pages: Page[] = [];
  try {
    // 2. Each person sees only their hosts and alarms, changes only their
    //    hosts, and cannot open Settings › Roles.
    const teams = [["linux", ["linux-1", "linux-2"], ["windows-1", "windows-2"]], ["windows", ["windows-1", "windows-2"], ["linux-1", "linux-2"]]] as const;
    for (const [os, mine, theirs] of teams) {
      const member = await firstSignIn(browser, `${os}-${tag}`, people[os].one_time_password);
      pages.push(member);
      await member.goto("/hosts");
      const hosts = member.getByRole("table", { name: "Hosts" }).locator("tbody tr");
      await expect(hosts).toHaveCount(2);
      for (const host of mine) await expect(hosts.filter({ hasText: host })).toHaveCount(1);
      await openFirstFinding(member);
      const inspector = member.locator(".inspector");
      for (const host of mine) await expect(inspector.getByText(host)).toHaveCount(1);
      for (const host of theirs) await expect(inspector.getByText(host)).toHaveCount(0);
      await member.goto("/alarms");
      const alarms = member.getByRole("table", { name: "Alarms" }).locator("tbody tr");
      await expect(alarms).toHaveCount(2);
      for (const host of mine) await expect(alarms.filter({ hasText: `Team alarm on ${host}` })).toHaveCount(1);
      await member.goto("/settings?tab=roles");
      await expect(member.getByRole("tab", { name: "Roles" })).toHaveCount(0);
      expect((await api(member, "GET", "/api/v1/roles")).status).toBe(403);
    }
    // Changes: the Linux person's bulk triage reaches linux-1, never windows-1.
    const [linux] = pages as [Page];
    const outside = await mitigate(linux, "windows-1");
    expect(outside.status === 200 ? (outside.json as { changed: number }).changed : 0).toBe(0);
    expect(await triageState(page, "windows-1")).toBe("open");
    const inside = await mitigate(linux, "linux-1");
    expect(inside.status).toBe(200);
    expect((inside.json as { changed: number }).changed).toBe(1);
    expect(await triageState(page, "linux-1")).toBe("mitigated");

    // 3. The Linux person also gets a Team lead role on Linux (plus adding people).
    const lead = templates.find((t) => t.name === "Team lead")?.permissions ?? [];
    const leadRole = await api(page, "POST", "/api/v1/roles", { name: `Linux lead ${tag}`, permissions: [...lead, "access.users"], reach: { kind: "groups", asset_group_ids: [groups.linux] } });
    expect(leadRole.status).toBe(201);
    const leadId = (leadRole.json as { role_id: string }).role_id;
    expect((await api(page, "PUT", `/api/v1/users/${people.linux.user_id}/roles/${leadId}`)).status).toBe(204);

    // 4. The lead adds a person with "Linux team"; "Windows team" is not offered, and refused.
    await linux.goto("/settings?tab=people");
    await linux.getByRole("button", { name: "New person" }).click();
    await linux.getByLabel("Username").fill(`new-${tag}`);
    await linux.getByLabel("Display name").fill("New Linux person");
    await linux.getByRole("combobox", { name: "Role" }).click();
    await expect(linux.getByRole("option", { name: new RegExp(`^Windows team ${tag}`) })).toHaveCount(0);
    await linux.getByRole("option", { name: new RegExp(`^Linux team ${tag}`) }).click();
    await linux.getByRole("button", { name: "Create person" }).click();
    await expect(linux.locator(".secret .grow")).not.toBeEmpty();
    const refused = await api(linux, "POST", "/api/v1/users", { username: `win-${tag}`, display_name: "Refused", role_ids: [roleIds.windows] });
    expect(refused.status).toBe(403);
    expect((refused.json as { title: string }).title).toMatch(/^You can only give roles that fit inside your own access \(.+ is outside it\)$/);
    // Nor to an existing person in the lead's reach.
    const listed = (await api(linux, "GET", "/api/v1/users")).json as { user_id: string; username: string }[];
    const added = listed.find((p) => p.username === `new-${tag}`);
    expect(added).toBeDefined();
    const give = await api(linux, "PUT", `/api/v1/users/${added?.user_id}/roles/${roleIds.windows}`);
    expect(give.status).toBe(403);
    expect((give.json as { title: string }).title).toMatch(/^You can only give roles that fit inside your own access/);
  } finally {
    for (const member of pages) await member.context().close();
  }
});

// Every host here but the team hosts has no alarm: a role on a group with no
// hosts sees the empty Alarms view and how to turn alarms on.
test("with no alarm in reach, the Alarms view says how to turn alarms on", async ({ page, browser }, info) => {
  const tag = `${info.project.name}-${Date.now().toString(36)}`;
  await signIn(page, "alex");
  const empty = await group(page, `no hosts ${tag}`, `none-${tag}`);
  const role = await api(page, "POST", "/api/v1/roles", { name: `Nobody ${tag}`, permissions: ANALYST, reach: { kind: "groups", asset_group_ids: [empty] } });
  expect(role.status).toBe(201);
  const created = await person(page, `nobody-${tag}`, (role.json as { role_id: string }).role_id);
  const member = await firstSignIn(browser, `nobody-${tag}`, created.one_time_password);
  try {
    await member.goto("/alarms");
    await expect(member.getByText("No alarms")).toBeVisible();
    await expect(member.getByText(/Agents report process starts by themselves/)).toBeVisible();
  } finally {
    await member.context().close();
  }
});
