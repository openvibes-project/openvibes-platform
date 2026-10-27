import { type Page, expect, test } from "@playwright/test";

import { expectNoAxeViolations, hostsCardParts } from "./list-helpers";

// A port's page on the demo (approved screen 20): the demo answers
// GET /api/v1/ports/{protocol}/{port}/summary and /hosts like ports/page.rs.
const { card, hosts } = hostsCardParts();
const segments = (page: Page) => page.getByRole("radiogroup", { name: "Hosts by exposure" });
const pickSegment = (page: Page, name: RegExp) => segments(page).getByRole("radio", { name }).click();

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.mouse.move(900, 500);
});

test("old_port_links_open_the_page: every spelling, as a panel or an address", async ({ page }) => {
  for (const open of ["port:tcp/22", "port:tcp:22", "port:22/tcp", "port:22"]) {
    await page.goto(`/hosts?open=${encodeURIComponent(open)}`);
    await expect(page).toHaveURL(/\/ports\/22\/tcp$/);
    await expect(page.locator(".detail-page h1")).toContainText("22/tcp");
    await expect(page.locator(".inspector")).toHaveCount(0);
  }
});

test("the header, tiles and cards say what listens, where and what changed", async ({ page }) => {
  await page.goto("/ports/22/tcp");
  const head = page.locator(".detail-page");
  await expect(head.locator("h1")).toContainText("22/tcp");
  await expect(head.locator("h1")).toContainText("SSH");
  await expect(head).toContainText("Secure remote login");
  await expect(page.locator(".detail-tiles")).toContainText("Listening");
  await expect(card(page, "Details")).toContainText("Usual use");
  await expect(card(page, "By group")).toBeVisible();
  await expect(card(page, "Recent changes")).toBeVisible();
  await expect(card(page, /^Hosts/)).toBeVisible();
  await expect(hosts(page).first()).toBeVisible();
  await expect(card(page, "Related")).toContainText("Failing checks");
  await expectNoAxeViolations(page);
});

test("switching the Hosts segments shows only those hosts, and the tiles lead there", async ({ page }) => {
  await page.goto("/ports/443/tcp");
  await expect(hosts(page).first()).toBeVisible();
  const all = await hosts(page).count();
  await pickSegment(page, /^Exposed/);
  await expect(page).toHaveURL(/segment=exposed/);
  for (const text of await hosts(page).allTextContents()) expect(text).toContain("exposed");
  await pickSegment(page, /^Local only/);
  for (const text of await hosts(page).allTextContents()) expect(text).toContain("local only");
  await pickSegment(page, /^All/);
  await expect(hosts(page)).toHaveCount(all);
  await expect(segments(page)).toBeVisible();
  await page.locator(".detail-tiles").getByRole("link", { name: /^Exposed:/ }).click();
  await expect(page).toHaveURL(/\/ports\/443\/tcp\?segment=exposed$/);
});

test("a host in the table opens its page", async ({ page }) => {
  await page.goto("/ports/22/tcp");
  await hosts(page).first().getByRole("link").first().click();
  await expect(page).toHaveURL(/\/hosts\/agent-\d{5}$/);
});

test("add to case puts the port in a case, and the Cases list counts it", async ({ page }) => {
  await page.goto("/ports/22/tcp");
  await expect(hosts(page).first()).toBeVisible();
  await page.getByRole("button", { name: "Add to case" }).click();
  const menu = page.getByRole("dialog", { name: /Add port to a case/ });
  await menu.getByRole("button", { name: "New case…" }).click();
  await menu.getByLabel("Title").fill("SSH exposure review");
  await menu.getByRole("button", { name: "Open case" }).click();
  await expect(page.locator(".toast")).toContainText(/Opened C-\d+/);
  // A port can be in many cases: the menu offers another.
  await expect(menu).toContainText("Also in:");
  await expectNoAxeViolations(page);
  await menu.getByRole("link", { name: /SSH exposure review/ }).click();
  await expect(page.getByRole("table", { name: "Items" })).toContainText("tcp/22");
});

test("export downloads a CSV of the hosts", async ({ page }) => {
  await page.goto("/ports/22/tcp");
  await page.getByRole("button", { name: "More actions" }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("menuitem", { name: /^Export/ }).click();
  const file = await download;
  expect(file.suggestedFilename()).toBe("openvibes-port-22-tcp.csv");
});

test("a port nothing listens on, and a bad address, say so", async ({ page }) => {
  await page.goto("/ports/4444/tcp");
  await expect(page.getByText("No such port")).toBeVisible();
  await page.goto("/ports/70000/tcp");
  await expect(page.getByText("No such port")).toBeVisible();
  await expectNoAxeViolations(page);
});

test("the page and its list never scroll sideways on a phone, and pass axe in dark", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const path of ["/ports", "/ports/22/tcp"]) {
    await page.goto(path);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/ports/22/tcp");
  await expect(hosts(page).first()).toBeVisible();
  await expectNoAxeViolations(page);
});
