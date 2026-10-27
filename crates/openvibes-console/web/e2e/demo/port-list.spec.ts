import { expect, test } from "@playwright/test";

import { expectNoAxeViolations, hideColumnAcrossReload, listParts, pointerOffRail, saveClearRestore } from "./list-helpers";

// The Ports list on the demo (approved screen 19): the demo answers
// GET /api/v1/port-list like ports/list_page.rs, over the listeners each
// host's role reports (demo/portData.ts).
const { table, rows, filters, choose } = listParts("Ports");
pointerOffRail();

test("filters by Exposure and Changes, and a reload keeps both", async ({ page }) => {
  await page.goto("/ports");
  await expect(rows(page).first()).toBeVisible();
  await expect(page.locator(".summary-line")).toContainText(/\d+ ports? reachable from the network · \d+ new this week · \d+ need a look · from \d+ hosts' last reports/);
  await choose(page, "Exposure", /^Exposed/);
  await choose(page, "Changes", /^New this week/);
  await expect(filters(page)).toContainText("Exposure: Exposed");
  await expect(filters(page)).toContainText("Changes: New this week");
  await expect(page).toHaveURL(/[?&]exposure=exposed/);
  await expect(page).toHaveURL(/[?&]changes=new/);
  const check = async () => {
    await expect(rows(page).filter({ hasText: "8888/tcp" })).toHaveCount(1);
    await expect(rows(page).filter({ hasText: "53/udp" })).toHaveCount(0);
  };
  await check();
  await page.reload();
  await expect(filters(page)).toContainText("Exposure: Exposed");
  await expect(filters(page)).toContainText("Changes: New this week");
  await check();
});

test("search finds a port by its usual name", async ({ page }) => {
  await page.goto("/ports");
  await expect(rows(page).first()).toBeVisible();
  await page.getByRole("searchbox", { name: "Search ports" }).fill("postgres");
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText("5432/tcp");
  await expect(rows(page).first()).toContainText("PostgreSQL");
});

test("a database reachable from the network needs a look; a row opens the port's page", async ({ page }) => {
  await page.goto("/ports?changes=look");
  await expect(rows(page).first()).toBeVisible();
  for (const text of await rows(page).allTextContents()) expect(text).toMatch(/reachable from the network|New this week, not a usual port/);
  await page.goto("/ports");
  await rows(page).filter({ hasText: "22/tcp" }).getByRole("link", { name: "22/tcp" }).click();
  await expect(page).toHaveURL(/\/ports\/22\/tcp$/);
  await expect(page.locator(".detail-page h1")).toContainText("22/tcp");
});

test("a saved view comes back after Clear all", async ({ page }) => {
  await page.goto("/ports?protocol=udp&sort=hosts&dir=desc");
  await expect(rows(page).first()).toBeVisible();
  await saveClearRestore(page, "UDP by hosts", /\/ports\?sort=hosts&dir=desc$/);
  await expect(filters(page)).toContainText("Protocol: UDP");
  for (const text of await rows(page).allTextContents()) expect(text).toContain("/udp");
});

test("a hidden column stays hidden after a reload; Port can't be hidden", async ({ page }) => {
  await page.goto("/ports");
  await hideColumnAcrossReload(page, table, rows, "Groups", ["Port"]);
});

test("the old ?exposed=true keeps its meaning", async ({ page }) => {
  await page.goto("/ports?exposed=true");
  await expect(rows(page).first()).toBeVisible();
  await expect(page).toHaveURL(/[?&]exposure=exposed/);
  await expect(page).not.toHaveURL(/exposed=true/);
  await expect(filters(page)).toContainText("Exposure: Exposed");
  await expect(rows(page).filter({ hasText: "22/tcp" })).toHaveCount(1);
  await expect(rows(page).filter({ hasText: "631/tcp" })).toHaveCount(0);
});

test("the list passes axe, and an empty one says why", async ({ page }) => {
  await page.goto("/ports");
  await expect(rows(page).first()).toBeVisible();
  await expectNoAxeViolations(page);
  await page.goto("/ports?q=nothing-called-this");
  await expect(page.getByText("No port matches these filters")).toBeVisible();
});
