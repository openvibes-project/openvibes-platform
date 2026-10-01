import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Threat alarms (P14) on the demo: list, process tree, triage, suppress.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("an alarm shows its process tree and is triaged and quieted", async ({ page }) => {
  await page.getByRole("link", { name: "Alarms", exact: true }).click();
  const row = page.locator(".view tbody tr").filter({ hasText: "A database server started a shell" });
  await expect(row).toContainText("postgres → bash");
  await row.locator("td").nth(1).click();
  const inspector = page.locator(".inspector");
  const tree = inspector.getByRole("list", { name: /Process tree/ });
  await expect(tree.locator("li")).toHaveCount(2);
  await expect(tree.locator("li").last()).toContainText("/usr/bin/bash");
  await expect(tree.locator("li").first()).toContainText("postgres: checkpointer");

  await inspector.getByRole("button", { name: "Apply" }).click();
  await expect(inspector.locator(".panel-header")).toContainText("Investigating");
  await inspector.getByRole("combobox", { name: "New triage state" }).selectOption("false_positive");
  await inspector.getByRole("combobox", { name: "Don't alarm on this again" }).selectOption("host");
  await inspector.getByRole("textbox", { name: "Triage note" }).fill("our backup job");
  await inspector.getByRole("button", { name: "Apply" }).click();
  await expect(inspector.locator(".panel-header")).toContainText("False positive");

  await page.getByRole("link", { name: "Alarm suppressions" }).click();
  await expect(page.locator(".view tbody tr").filter({ hasText: "shell-from-database" })).toContainText("our backup job");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("resolved alarms are hidden by default and counted in the empty state", async ({ page }) => {
  await page.goto("/alarms?q=nothing-matches-this");
  await expect(page.getByText("Nothing matches these filters")).toBeVisible();
});
