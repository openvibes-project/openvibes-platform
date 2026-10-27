// The Software list and a package's page on the real console (roles step
// 5g): a team lead sees only packages on their hosts, the counts agree with
// the rows, a package installed a day ago shows in This week and in the
// page's Recent changes, and the lead opens the page, switches segments and
// adds the package to a case. console-e2e-server.sh seeds one set per
// browser n: swlibN 1.0 on port-P-1 and port-P-2 (with an open
// vulnerability on port-P-1 that 1.1 fixes) and 1.1 on portout-P-1, swnewN on
// port-P-1 only, farN on portout-P-1 (outside
// the lead's reach). The browsers share one server, so every name carries
// the project's.
import { type Page, expect, test } from "@playwright/test";

import templates from "../../src/api/templates.json" with { type: "json" };
import { api, firstSignIn, signIn } from "./helpers";

type Count = { value: string; count: number };
type Row = {
  name: string; hosts: number; versions: number; advisories: number; update_hosts: number; worst_severity: string | null; week_added: number;
  used_by: { unit: string; hosts: number }[];
};
type List = { total: number; items: Row[]; counts: { group: { value: string; count: number }[]; fix: Count[] }; summary: { reporting_hosts: number; fixable: number } };

const N = { chromium: 1, firefox: 2, webkit: 3 } as const;
const rows = (page: Page) => page.getByRole("table", { name: "Software", exact: true }).locator("tbody tr");
const hostRows = (page: Page) => page.getByRole("table", { name: "Hosts", exact: true }).locator("tbody tr");
const list = async (page: Page, query = "") => (await api(page, "GET", `/api/v1/software-list?limit=100${query}`)).json as List;

test("a team lead's Software list and package page stay inside their team; an Administrator sees the rest", async ({ page, browser }, info) => {
  const n = N[info.project.name as keyof typeof N];
  const tag = `${info.project.name}-${Date.now().toString(36)}`;
  const [swlib, fresh, far] = [`swlib${n}`, `swnew${n}`, `far${n}`];
  await signIn(page, "alex");
  const created = await api(page, "POST", "/api/v1/host-groups", {
    name: `software ${tag}`, kind: "rule", conditions: [{ field: "hostname", negate: false, values: [`port-${info.project.name}-*`] }],
  });
  expect(created.status).toBe(201);
  const group = (created.json as { asset_group_id: string }).asset_group_id;
  const permissions = templates.find((t) => t.name === "Team lead")?.permissions ?? [];
  expect(permissions).not.toContain("hosts.export");
  const role = await api(page, "POST", "/api/v1/roles", { name: `Software lead ${tag}`, permissions, reach: { kind: "groups", asset_group_ids: [group] } });
  expect(role.status).toBe(201);
  const user = await api(page, "POST", "/api/v1/users", {
    username: `software-lead-${tag}`, display_name: "Software lead", role_ids: [(role.json as { role_id: string }).role_id],
  });
  expect(user.status).toBe(201);
  const lead = await firstSignIn(browser, `software-lead-${tag}`, (user.json as { one_time_password: string }).one_time_password);
  try {
    // 1. Only packages on the team's hosts, and the counts agree with the rows.
    await lead.goto("/software");
    await expect(rows(lead).first()).toBeVisible();
    const mine = await list(lead);
    expect(mine.items.map((r) => r.name)).toEqual([swlib, fresh]);
    await expect(lead.locator(".view-header__count")).toHaveText("2");
    await expect(rows(lead)).toHaveCount(2);
    const lib = mine.items.find((r) => r.name === swlib);
    expect([lib?.hosts, lib?.versions, lib?.advisories, lib?.update_hosts, lib?.worst_severity]).toEqual([2, 1, 1, 1, "important"]);
    expect(mine.summary.reporting_hosts).toBe(2);
    expect(mine.summary.fixable).toBe(1);
    expect(mine.counts.group.find((c) => c.value === group)?.count).toBe(2);
    const added = mine.items.find((r) => r.name === fresh);
    expect([added?.hosts, added?.week_added, added?.used_by]).toEqual([1, 1, []]);
    await expect(rows(lead).filter({ hasText: swlib })).toContainText("Update on 1");
    await expect(rows(lead).filter({ hasText: fresh })).toContainText("+1 new");

    // 2. A filter narrows both the rows and the counts; a reload keeps it.
    await lead.goto("/software?fix=available");
    await expect(rows(lead)).toHaveCount(1);
    await expect(rows(lead).first()).toContainText(swlib);
    await lead.reload();
    await expect(lead.getByRole("group", { name: "Filters" })).toContainText("Fix: Update available");
    await expect(rows(lead)).toHaveCount(1);

    // 3. The page: this team's hosts only, segments, and no Export without hosts.export.
    await lead.goto("/software");
    await rows(lead).filter({ hasText: swlib }).getByRole("link", { name: swlib }).click();
    await expect(lead).toHaveURL(new RegExp(`/software/${swlib}$`));
    await expect(lead.getByRole("heading", { level: 1 })).toContainText(swlib);
    await expect(hostRows(lead)).toHaveCount(2);
    await lead.getByRole("radiogroup", { name: "Hosts by whether they need an update" }).getByRole("radio", { name: /^Need an update/ }).click();
    await expect(hostRows(lead)).toHaveCount(1);
    await expect(hostRows(lead).first()).toContainText(`port-${info.project.name}-1`);
    await expect(hostRows(lead).first()).toContainText("Update to 1.1");
    await lead.getByRole("button", { name: "More actions" }).click();
    await expect(lead.getByRole("menuitem", { name: /^Export/ })).toHaveCount(0);
    await lead.keyboard.press("Escape");

    // 4. A package installed a day ago shows in Recent changes; one outside the reach is not there.
    await lead.goto(`/software/${fresh}`);
    await expect(lead.locator(".person-card").filter({ has: lead.getByRole("heading", { name: "Recent changes" }) })).toContainText(`port-${info.project.name}-1.example.test installed`);
    await lead.goto(`/software/${far}`);
    await expect(lead.getByText("No such package")).toBeVisible();
    expect((await api(lead, "GET", `/api/v1/software-pages/${far}/summary`)).status).toBe(404);

    // 5. Add the package to a case: it is in the case, and the case lists it.
    await lead.goto(`/software/${swlib}`);
    await expect(hostRows(lead).first()).toBeVisible();
    await lead.getByRole("button", { name: "Add to case" }).click();
    const menu = lead.getByRole("dialog", { name: /Add software to a case/ });
    await menu.getByRole("button", { name: "New case…" }).click();
    await menu.getByLabel("Title").fill(`swlib review ${tag}`);
    await menu.getByRole("button", { name: "Open case" }).click();
    await expect(lead.locator(".toast")).toContainText(/Opened C-\d+/);
    await menu.getByRole("link", { name: new RegExp(`swlib review ${tag}`) }).click();
    await expect(lead.locator(".person-card").filter({ has: lead.getByRole("heading", { name: /^Items/ }) }).locator("tr.case-row")).toContainText(swlib);

    // 6. An old link opens the page.
    await lead.goto(`/hosts?open=${encodeURIComponent(`package:dpkg/${swlib}`)}`);
    await expect(lead).toHaveURL(new RegExp(`/software/${swlib}$`));
  } finally {
    await lead.context().close();
  }

  // 7. The Administrator sees the outside host's package too, both versions, and may export.
  const all = await list(page);
  expect(all.items.map((r) => r.name)).toContain(far);
  expect(all.items.find((r) => r.name === swlib)).toMatchObject({ hosts: 3, versions: 2 });
  await page.goto(`/software/${swlib}`);
  await page.getByRole("button", { name: "More actions" }).click();
  await expect(page.getByRole("menuitem", { name: /^Export/ })).toBeVisible();
});
