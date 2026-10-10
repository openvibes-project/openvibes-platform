import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Bulk triage and the one detail view (triage v2, spec 2026-10-10).
// The demo keeps its data in memory: no test reloads mid-way.

// The pointer off the rail, which opens while hovered and covers the
// first columns.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.mouse.move(900, 500);
});

test("alarms are selected with a shift-click range and closed only with a note", async ({ page }) => {
  await page.goto("/alarms");
  const rows = page.locator(".view tbody tr");
  await expect(rows.first()).toBeVisible(); // count once the list has loaded
  const count = await rows.count();
  await rows.nth(0).getByRole("checkbox", { name: "Select row" }).check();
  await rows.nth(1).getByRole("checkbox", { name: "Select row" }).click({ modifiers: ["Shift"] });
  const bar = page.getByRole("region", { name: "Bulk actions" });
  await expect(bar).toContainText("2 selected");
  await bar.getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^False positive/ }).click();
  const dialog = page.getByRole("dialog", { name: "False positive" });
  await dialog.getByRole("button", { name: "Mark as false positive: 2 alarms" }).click();
  await expect(dialog.getByRole("alert")).toContainText("note");
  expect((await new AxeBuilder({ page }).include(".bulk-dialog").analyze()).violations).toEqual([]);
  await dialog.getByRole("textbox", { name: "Why (required)" }).fill("lab noise");
  await dialog.getByRole("button", { name: "Mark as false positive: 2 alarms" }).click();
  await expect(page.locator(".toast")).toContainText("2 changed");
  // Closed alarms leave the default list; the selection is gone.
  await expect(rows).toHaveCount(count - 2);
  await expect(bar).toHaveCount(0);
});

test("selected alarms go into a new case and the row shows it", async ({ page }) => {
  await page.goto("/alarms");
  const free = page.locator(".view tbody tr").filter({ hasNot: page.locator(".badge--info") }).first();
  const message = (await free.locator(".truncate").first().innerText()).trim();
  await free.getByRole("checkbox", { name: "Select row" }).check();
  await page.getByRole("region", { name: "Bulk actions" }).getByRole("button", { name: "Add to case" }).click();
  const dialog = page.getByRole("dialog", { name: "Add to case" });
  await dialog.getByRole("combobox", { name: "Case" }).click();
  await page.getByRole("option", { name: "New case…" }).click();
  await expect(dialog.getByLabel("New case title")).toHaveValue(/^1 alarms: /);
  await dialog.getByRole("button", { name: "Add 1 alarm to the case" }).click();
  await expect(page.locator(".toast")).toContainText(/1 changed in C-\d+/);
  await expect(page.locator(".view tbody tr").filter({ hasText: message }).locator(".badge--info")).toContainText(/C-\d+/);
});

test("a finding's Hosts tab lists every host, never cut off, and selects them for the bulk bar", async ({ page }) => {
  await page.goto("/compliance?open=finding%3Abaseline%2Fport.ssh.exposed");
  const inspector = page.locator(".inspector");
  const hostsTab = inspector.getByRole("tab", { name: /^Hosts/ });
  await expect(hostsTab).toHaveAttribute("aria-selected", "true");
  const total = Number((await hostsTab.innerText()).replace(/\D/g, ""));
  const hosts = inspector.locator("tbody tr");
  await expect(hosts).toHaveCount(total);
  const last = hosts.last();
  await last.scrollIntoViewIfNeeded();
  await expect(last).toBeInViewport();
  await inspector.getByRole("checkbox", { name: "Select the rows on screen" }).check();
  await expect(inspector.getByRole("region", { name: "Bulk actions" })).toContainText(`${total} selected`);
});

test("on a phone the bulk bar and the detail tabs fit the width", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/alarms");
  await page.locator(".view tbody tr").first().getByRole("checkbox", { name: "Select row" }).check();
  await expect(page.getByRole("region", { name: "Bulk actions" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.goto("/compliance?open=finding%3Abaseline%2Fport.ssh.exposed");
  await expect(page.getByRole("tablist")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
});
