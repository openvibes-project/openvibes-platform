import { expect, test } from "@playwright/test";

import { expectNoAxeViolations, hideColumnAcrossReload, listParts, pointerOffRail, saveClearRestore } from "./list-helpers";

// The Software list on the demo (approved screen 23): the demo answers
// GET /api/v1/software-list like software_pages/list_page.rs, over the
// packages each host's role reports (demo/softwareData.ts).
const { table, rows, filters, choose } = listParts("Software");
pointerOffRail();

test("lists one row per package, and the rail opens it", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: "Software", exact: true }).click();
  await expect(page).toHaveURL(/\/software$/);
  await expect(rows(page).filter({ hasText: /^bash/ })).toHaveCount(1);
  await expect(page.locator(".summary-line")).toContainText(/\d+ (has|have) an exploited vulnerability · \d+ (has|have) an update available · \d+ (has|have) several versions in use · \d+ new this week · from \d+ hosts' last reports/);
});

test("filters by Vulnerabilities and Fix, and a reload keeps both", async ({ page }) => {
  await page.goto("/software");
  await expect(rows(page).first()).toBeVisible();
  await choose(page, "Vulnerabilities", /^Any/);
  await choose(page, "Fix", /^Update available/);
  await expect(filters(page)).toContainText("Vulnerabilities: Any");
  await expect(filters(page)).toContainText("Fix: Update available");
  await expect(page).toHaveURL(/[?&]vulns=any/);
  await expect(page).toHaveURL(/[?&]fix=available/);
  const check = async () => {
    await expect(rows(page).first()).toBeVisible();
    for (const text of await rows(page).allTextContents()) expect(text).toMatch(/Update on \d+/);
  };
  await check();
  await page.reload();
  await expect(filters(page)).toContainText("Fix: Update available");
  await check();
});

test("the Versions filter keeps packages in several versions, and search finds a package", async ({ page }) => {
  await page.goto("/software?versions=several");
  await expect(rows(page).first()).toBeVisible();
  for (const text of await rows(page).allTextContents()) expect(text).toMatch(/\d+ versions/);
  await page.goto("/software");
  await page.getByRole("searchbox", { name: "Search software" }).fill("nginx");
  await expect(rows(page)).toHaveCount(1);
  await expect(rows(page).first()).toContainText("nginx");
});

test("a row opens the package's page, and a service in it opens the service's", async ({ page }) => {
  await page.goto("/software");
  await rows(page).filter({ hasText: /^openssl/ }).getByRole("link", { name: "openssl" }).click();
  await expect(page).toHaveURL(/\/software\/openssl$/);
  await expect(page.locator(".detail-page h1")).toContainText("openssl");
  await page.goto("/software?q=sshd");
  await expect(rows(page).first()).toBeVisible();
  await rows(page).first().getByRole("link", { name: "sshd", exact: true }).click();
  await expect(page).toHaveURL(/\/services\/sshd\.service$/);
});

test("a saved view comes back after Clear all", async ({ page }) => {
  await page.goto("/software?vulns=any&sort=hosts&dir=desc");
  await expect(rows(page).first()).toBeVisible();
  await saveClearRestore(page, "Vulnerable by hosts", /\/software\?sort=hosts&dir=desc$/);
  await expect(filters(page)).toContainText("Vulnerabilities: Any");
});

test("a hidden column stays hidden after a reload; Package can't be hidden", async ({ page }) => {
  await page.goto("/software");
  await hideColumnAcrossReload(page, table, rows, "Used by", ["Package"]);
});

test("the list passes axe, and an empty one says why", async ({ page }) => {
  await page.goto("/software");
  await expect(rows(page).first()).toBeVisible();
  await expectNoAxeViolations(page);
  await page.goto("/software?q=nothing-called-this");
  await expect(page.getByText("No package matches these filters")).toBeVisible();
});
