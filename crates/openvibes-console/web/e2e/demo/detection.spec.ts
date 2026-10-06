import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("a finding explains one host and opens its original rule", async ({ page }) => {
  await page.goto("/findings");
  const row = page.locator(".view tbody tr").filter({ hasText: "Listening service bound to all interfaces" });
  await row.locator("td").nth(1).click();
  const panel = page.locator(".inspector");
  await panel.getByRole("button", { name: "View evidence", exact: true }).first().click();
  await expect(panel.getByText("Complete list of 2 values", { exact: false })).toBeVisible();
  await panel.getByRole("button", { name: "View rule: LNX-060" }).click();
  await expect(panel.locator(".detection-rule code")).toHaveText('"6379" in facts["port.tcp.exposed"]');
  await expect(panel.locator(".detection-steps")).toContainText("True");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("an alarm opens the historical rule and evidence at a narrow width", async ({ page }) => {
  await page.goto("/alarms");
  const row = page.locator(".view tbody tr").filter({ hasText: "A database server started a shell" });
  await row.locator("td").nth(1).click();
  const panel = page.locator(".inspector");
  await panel.getByRole("button", { name: "View rule: shell-from-database" }).click();
  await expect(panel.locator(".detection-rule code")).toContainText('/usr/bin/postgres');
  await expect(panel.locator(".detection-inputs")).toContainText('/usr/bin/bash');
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});
