import { type Page, expect, test } from "@playwright/test";

import { expectNoAxeViolations, hostsCardParts } from "./list-helpers";

// A service's page on the demo (approved screen 22): the demo answers
// GET /api/v1/services/{unit}/summary and /hosts like services/page.rs.
const { card, hosts } = hostsCardParts();
const segments = (page: Page) => page.getByRole("radiogroup", { name: "Hosts by exposure and user" });
const pickSegment = (page: Page, name: RegExp) => segments(page).getByRole("radio", { name }).click();

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.mouse.move(900, 500);
});

test("old_unit_links_open_the_page: as a panel or an address", async ({ page }) => {
  await page.goto(`/hosts?open=${encodeURIComponent("unit:sshd.service")}`);
  await expect(page).toHaveURL(/\/services\/sshd\.service$/);
  await expect(page.locator(".detail-page h1")).toContainText("sshd.service");
  await expect(page.locator(".inspector")).toHaveCount(0);
});

test("the header, tiles and cards say what runs, where and what changed", async ({ page }) => {
  await page.goto("/services/sshd.service");
  const head = page.locator(".detail-page");
  await expect(head.locator("h1")).toContainText("sshd.service");
  await expect(head.locator("h1")).toContainText("OpenSSH server");
  await expect(head).toContainText("Secure remote login");
  await expect(page.locator(".detail-tiles")).toContainText("Running on");
  await expect(card(page, "Details")).toContainText("Runs as");
  await expect(card(page, "Ports")).toContainText("22/tcp");
  await expect(card(page, "By group")).toBeVisible();
  await expect(card(page, "Recent changes")).toBeVisible();
  await expect(card(page, /^Hosts/)).toBeVisible();
  await expect(hosts(page).first()).toBeVisible();
  await expect(card(page, "Related")).toContainText("Failing checks");
  await expectNoAxeViolations(page);
});

test("switching the Hosts segments shows only those hosts, and the tile leads there", async ({ page }) => {
  await page.goto("/services/sshd.service");
  await expect(hosts(page).first()).toBeVisible();
  const all = await hosts(page).count();
  await pickSegment(page, /^Exposed/);
  await expect(page).toHaveURL(/segment=exposed/);
  for (const text of await hosts(page).allTextContents()) expect(text).toContain("22/tcp");
  await pickSegment(page, /^Runs as root/);
  for (const text of await hosts(page).allTextContents()) expect(text).toContain("as root");
  await pickSegment(page, /^All/);
  await expect(hosts(page)).toHaveCount(all);
  await page.locator(".detail-tiles").getByRole("link", { name: /^Running on/ }).click();
  await expect(page).toHaveURL(/#hosts$/);
});

test("a host in the table opens its page, a port in the card opens the port's", async ({ page }) => {
  await page.goto("/services/sshd.service");
  await hosts(page).first().getByRole("link").first().click();
  await expect(page).toHaveURL(/\/hosts\/agent-\d{5}$/);
  await page.goto("/services/sshd.service");
  await card(page, "Ports").getByRole("link", { name: "22/tcp" }).click();
  await expect(page).toHaveURL(/\/ports\/22\/tcp$/);
});

test("add to case puts the service in a case, and the case lists it", async ({ page }) => {
  await page.goto("/services/sshd.service");
  await expect(hosts(page).first()).toBeVisible();
  await page.getByRole("button", { name: "Add to case" }).click();
  const menu = page.getByRole("dialog", { name: /Add service to a case/ });
  await menu.getByRole("button", { name: "New case…" }).click();
  await menu.getByLabel("Title").fill("sshd review");
  await menu.getByRole("button", { name: "Open case" }).click();
  await expect(page.locator(".toast")).toContainText(/Opened C-\d+/);
  await expect(menu).toContainText("Also in:");
  await expectNoAxeViolations(page);
  await menu.getByRole("link", { name: /sshd review/ }).click();
  await expect(page.getByRole("table", { name: "Items" })).toContainText("sshd.service");
});

test("export downloads a CSV of the hosts", async ({ page }) => {
  await page.goto("/services/sshd.service");
  await page.getByRole("button", { name: "More actions" }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("menuitem", { name: /^Export/ }).click();
  const file = await download;
  expect(file.suggestedFilename()).toBe("openvibes-service-sshd.service.csv");
});

test("a service nothing runs says so", async ({ page }) => {
  await page.goto("/services/nothing.service");
  await expect(page.getByText("No such service")).toBeVisible();
  await expectNoAxeViolations(page);
});

test("the page and its list never scroll sideways on a phone, and pass axe in dark", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const path of ["/services", "/services/sshd.service"]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/services/sshd.service");
  await expect(hosts(page).first()).toBeVisible();
  await expectNoAxeViolations(page);
});
