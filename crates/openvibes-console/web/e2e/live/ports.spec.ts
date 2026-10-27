// The Ports list and a port's page on the real console (roles step 5e): a
// team lead sees only ports on their hosts, the counts agree with the rows,
// a port started a day ago shows in This week and in the page's Recent
// changes, and the lead opens the page, switches segments and adds the port
// to a case. console-e2e-server.sh seeds one set per browser P = n:
// port-P-1 and port-P-2 (the lead's reach) and portout-P-1 (outside it).
// The browsers share one server, so every name carries the project's.
import { type Page, expect, test } from "@playwright/test";

import templates from "../../src/api/templates.json" with { type: "json" };
import { api, firstSignIn, signIn } from "./helpers";

type Count = { value: string; count: number };
type Row = { protocol: string; port: number; hosts: number; exposed_hosts: number; week_added: number; look: string[]; owners_missing: boolean };
type List = { total: number; items: Row[]; counts: { exposure: Count[]; changes: Count[]; group: Count[] }; summary: { reporting_hosts: number } };

const N = { chromium: 1, firefox: 2, webkit: 3 } as const;
const rows = (page: Page) => page.getByRole("table", { name: "Ports", exact: true }).locator("tbody tr");
const hostRows = (page: Page) => page.getByRole("table", { name: "Hosts", exact: true }).locator("tbody tr");
const list = async (page: Page, query = "") => (await api(page, "GET", `/api/v1/port-list?limit=100${query}`)).json as List;
const countOf = (counts: Count[], value: string) => counts.find((c) => c.value === value)?.count ?? 0;

test("a team lead's Ports list and port page stay inside their team; an Administrator sees the rest", async ({ page, browser }, info) => {
  const n = N[info.project.name as keyof typeof N];
  const tag = `${info.project.name}-${Date.now().toString(36)}`;
  await signIn(page, "alex");
  const created = await api(page, "POST", "/api/v1/host-groups", {
    name: `ports ${tag}`, kind: "rule", conditions: [{ field: "hostname", negate: false, values: [`port-${info.project.name}-*`] }],
  });
  expect(created.status).toBe(201);
  const group = (created.json as { asset_group_id: string }).asset_group_id;
  const permissions = templates.find((t) => t.name === "Team lead")?.permissions ?? [];
  expect(permissions).not.toContain("hosts.export");
  const role = await api(page, "POST", "/api/v1/roles", { name: `Ports lead ${tag}`, permissions, reach: { kind: "groups", asset_group_ids: [group] } });
  expect(role.status).toBe(201);
  const user = await api(page, "POST", "/api/v1/users", {
    username: `ports-lead-${tag}`, display_name: "Ports lead", role_ids: [(role.json as { role_id: string }).role_id],
  });
  expect(user.status).toBe(201);
  const lead = await firstSignIn(browser, `ports-lead-${tag}`, (user.json as { one_time_password: string }).one_time_password);
  try {
    // 1. Only ports on the team's hosts, and the counts agree with the rows.
    const started = 8000 + n;
    await lead.goto("/ports");
    await expect(rows(lead).first()).toBeVisible();
    const mine = await list(lead);
    const keys = mine.items.map((r) => `${r.port}/${r.protocol}`);
    expect(keys).toEqual(["22/tcp", "5432/tcp", `${started}/tcp`]);
    expect(keys).not.toContain(`${7000 + n}/tcp`);
    await expect(lead.locator(".view-header__count")).toHaveText("3");
    await expect(rows(lead)).toHaveCount(3);
    const ssh = mine.items.find((r) => r.port === 22);
    expect([ssh?.hosts, ssh?.exposed_hosts]).toEqual([2, 1]);
    expect(mine.summary.reporting_hosts).toBe(2);
    expect(countOf(mine.counts.group, group)).toBe(3);
    // The Needs a look and This week cells agree with the API.
    expect(mine.items.find((r) => r.port === 5432)?.look).toEqual(["database_exposed"]);
    const fresh = mine.items.find((r) => r.port === started);
    expect([fresh?.week_added, fresh?.owners_missing, fresh?.look]).toEqual([1, true, ["new_unusual"]]);
    await expect(rows(lead).filter({ hasText: "5432/tcp" })).toContainText("Database reachable from the network");
    await expect(rows(lead).filter({ hasText: `${started}/tcp` })).toContainText("+1 host");

    // 2. A filter narrows both the rows and the counts; a reload keeps it.
    await lead.goto("/ports?changes=new");
    await expect(rows(lead)).toHaveCount(1);
    await expect(rows(lead).first()).toContainText(`${started}/tcp`);
    await lead.reload();
    await expect(lead.getByRole("group", { name: "Filters" })).toContainText("Changes: New this week");
    await expect(rows(lead)).toHaveCount(1);

    // 3. The page: this team's hosts only, segments, and no Export without hosts.export.
    await lead.goto("/ports");
    await rows(lead).filter({ hasText: "22/tcp" }).getByRole("link", { name: "22/tcp" }).click();
    await expect(lead).toHaveURL(/\/ports\/22\/tcp$/);
    await expect(lead.getByRole("heading", { level: 1 })).toContainText("22/tcp");
    await expect(hostRows(lead)).toHaveCount(2);
    await lead.getByRole("radiogroup", { name: "Hosts by exposure" }).getByRole("radio", { name: /^Exposed/ }).click();
    await expect(hostRows(lead)).toHaveCount(1);
    await expect(hostRows(lead).first()).toContainText(`port-${info.project.name}-1`);
    await lead.getByRole("radiogroup", { name: "Hosts by exposure" }).getByRole("radio", { name: /^Local only/ }).click();
    await expect(hostRows(lead).first()).toContainText(`port-${info.project.name}-2`);
    await lead.getByRole("button", { name: "More actions" }).click();
    await expect(lead.getByRole("menuitem", { name: /^Export/ })).toHaveCount(0);
    await lead.keyboard.press("Escape");

    // 4. A port started a day ago shows in Recent changes; one outside the reach is not there.
    await lead.goto(`/ports/${started}/tcp`);
    await expect(lead.locator(".person-card").filter({ has: lead.getByRole("heading", { name: "Recent changes" }) })).toContainText(`port-${info.project.name}-1.example.test started listening`);
    await lead.goto(`/ports/${7000 + n}/tcp`);
    await expect(lead.getByText("No such port")).toBeVisible();
    expect((await api(lead, "GET", `/api/v1/ports/tcp/${7000 + n}/summary`)).status).toBe(404);

    // 5. Add the port to a case: it is in the case, and the case lists it.
    await lead.goto("/ports/22/tcp");
    await expect(hostRows(lead).first()).toBeVisible();
    await lead.getByRole("button", { name: "Add to case" }).click();
    const menu = lead.getByRole("dialog", { name: /Add port to a case/ });
    await menu.getByRole("button", { name: "New case…" }).click();
    await menu.getByLabel("Title").fill(`SSH review ${tag}`);
    await menu.getByRole("button", { name: "Open case" }).click();
    await expect(lead.locator(".toast")).toContainText(/Opened C-\d+/);
    await menu.getByRole("link", { name: new RegExp(`SSH review ${tag}`) }).click();
    await expect(lead.locator(".person-card").filter({ has: lead.getByRole("heading", { name: /^Items/ }) }).locator("tr.case-row")).toContainText("tcp/22");

    // 6. An old link opens the page, whichever way it spells the port.
    await lead.goto(`/hosts?open=${encodeURIComponent("port:tcp:22")}`);
    await expect(lead).toHaveURL(/\/ports\/22\/tcp$/);
  } finally {
    await lead.context().close();
  }

  // 7. The Administrator sees the outside host's port too, and may export.
  const all = await list(page);
  expect(all.items.map((r) => `${r.port}/${r.protocol}`)).toContain(`${7000 + n}/tcp`);
  await page.goto("/ports/22/tcp");
  await page.getByRole("button", { name: "More actions" }).click();
  await expect(page.getByRole("menuitem", { name: /^Export/ })).toBeVisible();
});
