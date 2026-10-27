import { expect, test } from "@playwright/test";

import { expectNoAxeViolations, hideColumnAcrossReload, listParts, pointerOffRail, saveClearRestore } from "./list-helpers";

// The Services list on the demo (approved screen 21): the demo answers
// GET /api/v1/service-list like services/list_page.rs, over the units each
// host's role reports (demo/serviceData.ts).
const { table, rows, filters, choose } = listParts("Services");
pointerOffRail();

test("filters by Runs as and Listens, and a reload keeps both", async ({ page }) => {
  await page.goto("/services");
  await expect(rows(page).first()).toBeVisible();
  await expect(page.locator(".summary-line")).toContainText(/\d+ services? runs? as root · \d+ listens? on an exposed port · \d+ not from a package · \d+ new this week · \d+ need a look · from \d+ hosts' last reports/);
  await choose(page, "Runs as", /^Another user/);
  await choose(page, "Listens", /^On an exposed port/);
  await expect(filters(page)).toContainText("Runs as: Another user");
  await expect(filters(page)).toContainText("Listens: On an exposed port");
  await expect(page).toHaveURL(/[?&]runs_as=other/);
  await expect(page).toHaveURL(/[?&]listens=exposed/);
  const check = async () => {
    await expect(rows(page).filter({ hasText: "postgresql.service" })).toHaveCount(1);
    await expect(rows(page).filter({ hasText: "sshd.service" })).toHaveCount(0);
  };
  await check();
  await page.reload();
  await expect(filters(page)).toContainText("Runs as: Another user");
  await check();
});

test("search finds a service by its usual name", async ({ page }) => {
  await page.goto("/services");
  await expect(rows(page).first()).toBeVisible();
  await page.getByRole("searchbox", { name: "Search services" }).fill("openssh");
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText("sshd.service");
  await expect(rows(page).first()).toContainText("OpenSSH server");
});

test("a database reachable from the network needs a look; a row opens the service's page", async ({ page }) => {
  await page.goto("/services?changes=look");
  await expect(rows(page).first()).toBeVisible();
  for (const text of await rows(page).allTextContents()) expect(text).toMatch(/not from a package|reachable from the network|New this week, not a usual service|Runs as root/);
  await page.goto("/services");
  await rows(page).filter({ hasText: "sshd.service" }).getByRole("link", { name: "sshd.service" }).click();
  await expect(page).toHaveURL(/\/services\/sshd\.service$/);
  await expect(page.locator(".detail-page h1")).toContainText("sshd.service");
});

test("an owned port links to the port's page", async ({ page }) => {
  await page.goto("/services?q=postgres");
  await rows(page).first().getByRole("link", { name: "5432/tcp" }).click();
  await expect(page).toHaveURL(/\/ports\/5432\/tcp$/);
});

test("a saved view comes back after Clear all", async ({ page }) => {
  await page.goto("/services?runs_as=root&sort=hosts&dir=desc");
  await expect(rows(page).first()).toBeVisible();
  await saveClearRestore(page, "Root by hosts", /\/services\?sort=hosts&dir=desc$/);
  await expect(filters(page)).toContainText("Runs as: Root or SYSTEM");
});

test("a hidden column stays hidden after a reload; Service can't be hidden", async ({ page }) => {
  await page.goto("/services");
  await hideColumnAcrossReload(page, table, rows, "Ports", ["Service"]);
});

test("the list passes axe, and an empty one says why", async ({ page }) => {
  await page.goto("/services");
  await expect(rows(page).first()).toBeVisible();
  await expectNoAxeViolations(page);
  await page.goto("/services?q=nothing-called-this");
  await expect(page.getByText("No service matches these filters")).toBeVisible();
});
