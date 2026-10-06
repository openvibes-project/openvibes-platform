import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("a finding explains one host and opens its original rule", async ({ page }) => {
  await page.goto("/findings");
  const row = page.locator(".view tbody tr").filter({ hasText: "Listening service bound to all interfaces" });
  await row.locator("td").nth(1).click();
  const panel = page.locator(".inspector");
  await panel.getByRole("button", { name: "View evidence", exact: true }).first().click();
  await expect(panel.getByText("Complete list of 2 values", { exact: false })).toBeVisible();
  await expect(panel.locator(".detection-verdict")).toContainText("Matched 1 of 1 condition");
  await panel.getByRole("button", { name: "Show rule" }).click();
  await expect(panel.locator(".detection-code code").first()).toHaveText('"6379" in facts["port.tcp.exposed"]');
  await expect(panel.locator(".detection-steps")).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("an alarm opens the historical rule and evidence at a narrow width", async ({ page }) => {
  await page.goto("/alarms");
  const row = page.locator(".view tbody tr").filter({ hasText: "A database server started a shell" });
  await row.locator("td").nth(1).click();
  const panel = page.locator(".inspector");
  await panel.getByRole("button", { name: "Show rule" }).click();
  await expect(panel.locator(".detection-code code").first()).toContainText('/usr/bin/postgres');
  await expect(panel.locator(".detection-inputs")).toContainText('/usr/bin/bash');
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});
