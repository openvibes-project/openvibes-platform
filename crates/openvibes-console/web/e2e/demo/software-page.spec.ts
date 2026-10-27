import { type Page, expect, test } from "@playwright/test";

import { expectNoAxeViolations, hostsCardParts } from "./list-helpers";

// A package's page on the demo (approved screen 24): the demo answers
// GET /api/v1/software-pages/{name}/summary and /hosts like
// software_pages/page.rs.
const { card, hosts } = hostsCardParts();
const segments = (page: Page) => page.getByRole("radiogroup", { name: "Hosts by whether they need an update" });
const pickSegment = (page: Page, name: RegExp) => segments(page).getByRole("radio", { name }).click();

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.mouse.move(900, 500);
});

test("old_package_links_open_the_page: as a panel or an address", async ({ page }) => {
  await page.goto(`/hosts?open=${encodeURIComponent("package:rpm/openssl")}`);
  await expect(page).toHaveURL(/\/software\/openssl$/);
  await expect(page.locator(".detail-page h1")).toContainText("openssl");
  await expect(page.locator(".inspector")).toHaveCount(0);
});

test("the header, tiles and cards say what has it, which versions and what to update", async ({ page }) => {
  await page.goto("/software/openssl");
  const head = page.locator(".detail-page");
  await expect(head.locator("h1")).toContainText("openssl");
  const tiles = page.locator(".detail-tiles");
  for (const label of ["Hosts that have it", "Open vulnerabilities", "Hosts that need an update", "Versions in use"]) await expect(tiles).toContainText(label);
  await expect(card(page, "Details")).toContainText("Most hosts run");
  await expect(card(page, /^Versions/)).toBeVisible();
  await expect(card(page, "Used by")).toBeVisible();
  await expect(card(page, "By group")).toBeVisible();
  await expect(card(page, "Recent changes")).toBeVisible();
  await expect(card(page, /^Vulnerabilities/)).toBeVisible();
  await expect(hosts(page).first()).toBeVisible();
  await expectNoAxeViolations(page);
});

test("switching the Hosts segments shows only those hosts", async ({ page }) => {
  await page.goto("/software/openssl");
  await expect(hosts(page).first()).toBeVisible();
  const all = await hosts(page).count();
  await pickSegment(page, /^Need an update/);
  await expect(page).toHaveURL(/segment=update/);
  for (const text of await hosts(page).allTextContents()) expect(text).toContain("Update to");
  await pickSegment(page, /^Up to date/);
  for (const text of await hosts(page).allTextContents()) expect(text).toContain("Up to date");
  await pickSegment(page, /^All/);
  await expect(hosts(page)).toHaveCount(all);
  await page.locator(".detail-tiles").getByRole("link", { name: /^Hosts that need an update/ }).click();
  await expect(page).toHaveURL(/segment=update/);
});

test("a host in the table opens its page, a vulnerability opens its own", async ({ page }) => {
  await page.goto("/software/openssl");
  await hosts(page).first().getByRole("link").first().click();
  await expect(page).toHaveURL(/\/hosts\/agent-\d{5}$/);
  await page.goto("/software/openssl");
  await card(page, /^Vulnerabilities/).getByRole("link").first().click();
  // A vulnerability naming several CVEs opens the list filtered by it (screen 26).
  await expect(page).toHaveURL(/\/vulnerabilities(\/[^?]+|\?advisory=[^&]+&state=all)$/);
});

test("add to case puts the package in a case, and the case lists it", async ({ page }) => {
  await page.goto("/software/openssl");
  await expect(hosts(page).first()).toBeVisible();
  await page.getByRole("button", { name: "Add to case" }).click();
  const menu = page.getByRole("dialog", { name: /Add software to a case/ });
  await menu.getByRole("button", { name: "New case…" }).click();
  await menu.getByLabel("Title").fill("openssl review");
  await menu.getByRole("button", { name: "Open case" }).click();
  await expect(page.locator(".toast")).toContainText(/Opened C-\d+/);
  await expect(menu).toContainText("Also in:");
  await menu.getByRole("link", { name: /openssl review/ }).click();
  await expect(page.getByRole("table", { name: "Items" })).toContainText("openssl");
});

test("export downloads a CSV of the hosts", async ({ page }) => {
  await page.goto("/software/openssl");
  await page.getByRole("button", { name: "More actions" }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("menuitem", { name: /^Export/ }).click();
  expect((await download).suggestedFilename()).toBe("openvibes-software-openssl.csv");
});

test("a package no host has says so", async ({ page }) => {
  await page.goto("/software/nothing-at-all");
  await expect(page.getByText("No such package")).toBeVisible();
  await expectNoAxeViolations(page);
});

test("the page and its list never scroll sideways on a phone, and pass axe in dark", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const path of ["/software", "/software/openssl"]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/software/openssl");
  await expect(hosts(page).first()).toBeVisible();
  await expectNoAxeViolations(page);
});
