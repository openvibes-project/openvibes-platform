import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("a check's failing host explains itself and opens its original rule", async ({ page }) => {
  await page.goto("/compliance/baseline/port.redis.exposed?segment=failing");
  const panel = page.locator(".person-card").filter({ has: page.getByRole("heading", { name: /^Hosts/ }) });
  await panel.getByRole("button", { name: /^View evidence on / }).first().click();
  await expect(panel.getByText("Complete list of 2 values", { exact: false })).toBeVisible();
  await expect(panel.locator(".detection-verdict")).toContainText("Matched 1 of 1 condition");
  await panel.getByRole("button", { name: "Show rule" }).click();
  await expect(panel.locator(".detection-code code").first()).toHaveText("'6379' in facts['port.tcp.exposed']");
  await expect(panel.locator(".detection-steps")).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("an alarm opens the historical rule and evidence at a narrow width", async ({ page }) => {
  await page.goto("/alarms");
  const row = page.locator(".view tbody tr").filter({ hasText: "A database server started a shell" });
  await row.locator("td").nth(2).click();
  // The alarm's page (screen 30): the evidence is in What happened.
  await expect(page).toHaveURL(/\/alarms\/\d+$/);
  const panel = page.locator(".view");
  await panel.getByRole("button", { name: "Show rule" }).click();
  await expect(panel.locator(".detection-code code").first()).toContainText('/usr/bin/postgres');
  await expect(panel.locator(".detection-inputs")).toContainText('/usr/bin/bash');
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

// The finding panel's host Select is gone with the panel (a check's page,
// screen 28, opens each host's evidence from its row); the Select's filter,
// typed-letter and pick behaviour is covered on the dashboard editor
// (dashboards.spec.ts), its phone placement here on the Compliance list.
test("a Select opens by keyboard, never clipped at 390 px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/compliance");
  const host = page.getByRole("group", { name: "Filters" }).getByRole("combobox", { name: "Rule set" });
  await host.focus();
  await page.keyboard.press("ArrowDown");
  const popup = page.locator(".sel__popup");
  await expect(host).toHaveAttribute("aria-expanded", "true");
  const box = await popup.boundingBox();
  expect(box?.x ?? -1).toBeGreaterThanOrEqual(0);
  expect((box?.x ?? 999) + (box?.width ?? 999)).toBeLessThanOrEqual(390);
  await page.keyboard.press("Escape");
  await expect(popup).toHaveCount(0);
  await expect(host).toBeFocused();
});
