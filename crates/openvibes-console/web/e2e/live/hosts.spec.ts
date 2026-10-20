// The Hosts list and the host page on the real console (roles step 4): a
// Linux team lead sees only linux-1/2 (console-e2e-server.sh, one alarm
// each), the list's counts agree with its rows, a saved view lives on the
// console, and the host page offers no Revoke without hosts.revoke; an
// Administrator's counts include both teams. The browsers share one server,
// so every name carries the project's.
import { type Page, expect, test } from "@playwright/test";

import templates from "../../src/api/templates.json" with { type: "json" };
import { api, firstSignIn, signIn } from "./helpers";

type Count = { value: string; count: number };
type List = { total: number; items: { id: string; hostname: string | null }[]; counts: { os: Count[]; group: Count[]; problems: Count[] } };

const rows = (page: Page) => page.getByRole("table", { name: "Hosts" }).locator("tbody tr");
const list = async (page: Page, query = "") => (await api(page, "GET", `/api/v1/hosts?limit=100${query}`)).json as List;
const countOf = (counts: Count[], value: string) => counts.find((c) => c.value === value)?.count ?? 0;

/** A rule group "hostname matches `<prefix>-*`", made by the signed-in Administrator. */
async function group(page: Page, name: string, prefix: string) {
  const created = await api(page, "POST", "/api/v1/host-groups", {
    name, kind: "rule", conditions: [{ field: "hostname", negate: false, values: [`${prefix}-*`] }],
  });
  expect(created.status).toBe(201);
  return (created.json as { asset_group_id: string }).asset_group_id;
}

test("a team lead's Hosts list, saved view and host page stay inside their team; an Administrator counts both teams", async ({ page, browser }, info) => {
  const tag = `${info.project.name}-${Date.now().toString(36)}`;
  await signIn(page, "alex");
  const linux = await group(page, `hosts linux ${tag}`, "linux");
  const windows = await group(page, `hosts windows ${tag}`, "windows");
  const permissions = templates.find((t) => t.name === "Team lead")?.permissions ?? [];
  expect(permissions).not.toContain("hosts.revoke");
  const role = await api(page, "POST", "/api/v1/roles", { name: `Hosts lead ${tag}`, permissions, reach: { kind: "groups", asset_group_ids: [linux] } });
  expect(role.status).toBe(201);
  const created = await api(page, "POST", "/api/v1/users", {
    username: `hosts-lead-${tag}`, display_name: "Hosts lead", role_ids: [(role.json as { role_id: string }).role_id],
  });
  expect(created.status).toBe(201);
  const lead = await firstSignIn(browser, `hosts-lead-${tag}`, (created.json as { one_time_password: string }).one_time_password);
  try {
    // 1. Only the team's hosts, and the counts agree with the rows.
    await lead.goto("/hosts");
    await expect(rows(lead)).toHaveCount(2);
    for (const host of ["linux-1", "linux-2"]) await expect(rows(lead).filter({ hasText: host })).toHaveCount(1);
    await expect(lead.locator(".view-header__count")).toHaveText("2");
    const mine = await list(lead);
    expect(mine.total).toBe(2);
    expect(mine.items.every((h) => h.hostname?.startsWith("linux-"))).toBe(true);
    expect(countOf(mine.counts.os, "linux")).toBe(2);
    expect(countOf(mine.counts.os, "windows")).toBe(0);
    expect(countOf(mine.counts.group, linux)).toBe(2);
    expect(countOf(mine.counts.group, windows)).toBe(0);
    expect(countOf(mine.counts.problems, "alarms")).toBe(2);

    // 2. A saved view lives on the console: it is there after a reload.
    await lead.goto("/hosts?os=linux");
    await expect(rows(lead)).toHaveCount(2);
    await lead.getByRole("button", { name: "Save view" }).click();
    await lead.getByRole("textbox", { name: "View name" }).fill(`Linux ${tag}`);
    await lead.keyboard.press("Enter");
    await expect(lead.locator(".toast").last()).toContainText(`View “Linux ${tag}” saved`);
    await lead.getByRole("button", { name: "Clear all" }).click();
    await expect(lead).toHaveURL(/\/hosts$/);
    await lead.reload();
    await lead.getByRole("group", { name: "Saved views" }).getByRole("button", { name: `Linux ${tag}`, exact: true }).click();
    await expect(lead).toHaveURL(/[?&]os=linux/);
    await expect(lead.getByRole("group", { name: "Filters" })).toContainText("OS: Linux");

    // 3. The host page: no Revoke without hosts.revoke.
    await rows(lead).filter({ hasText: "linux-1" }).locator("td").nth(1).click();
    await expect(lead).toHaveURL(/\/hosts\/agent\.[0-9a-f-]+$/);
    await expect(lead.getByRole("heading", { level: 1 })).toContainText("linux-1");
    await expect(lead.getByRole("button", { name: "More actions" })).toHaveCount(0);
    await expect(lead.getByRole("menuitem", { name: /Revoke/ })).toHaveCount(0);
  } finally {
    await lead.context().close();
  }

  // 4. The Administrator's counts include both teams.
  const all = await list(page);
  expect(countOf(all.counts.group, linux)).toBe(2);
  expect(countOf(all.counts.group, windows)).toBe(2);
  expect(countOf(all.counts.os, "windows")).toBeGreaterThanOrEqual(2);
  expect(all.total).toBeGreaterThanOrEqual(4);
  await page.goto(`/hosts?group=${windows}`);
  await expect(rows(page)).toHaveCount(2);
  for (const host of ["windows-1", "windows-2"]) await expect(rows(page).filter({ hasText: host })).toHaveCount(1);
});
