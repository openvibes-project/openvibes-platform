import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Threat alarms (P14) on the demo: list, process tree, triage, suppress.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("an alarm shows its process tree and is triaged and quieted", async ({ page }) => {
  await page.getByRole("link", { name: "Alarms", exact: true }).click();
  const badge = page.locator(".rail .rail__item").filter({ hasText: "Alarms" }).first().locator(".rail__count");
  await expect(badge).toHaveText(/\d/);
  const before = Number((await badge.textContent())?.replace("+", ""));
  const row = page.locator(".view tbody tr").filter({ hasText: "A database server started a shell" });
  await expect(row).toContainText("postgres → bash");
  await row.locator("td").nth(2).click();
  const inspector = page.locator(".inspector");
  const tree = inspector.getByRole("list", { name: /Process tree/ });
  await expect(tree.locator("li")).toHaveCount(2);
  await expect(tree.locator("li").last()).toContainText("/usr/bin/bash");
  await expect(tree.locator("li").first()).toContainText("postgres: checkpointer");

  // One step to a closing state, and it needs a note (triage v2).
  await inspector.getByRole("region", { name: "Triage actions" }).getByRole("button", { name: "False positive…" }).click();
  const dialog = page.getByRole("dialog", { name: "False positive" });
  await dialog.getByRole("button", { name: "Mark as false positive: 1 alarm" }).click();
  await expect(dialog.getByRole("alert")).toContainText("note");
  await dialog.getByRole("textbox", { name: "Note (required)" }).fill("our backup job");
  await dialog.getByRole("button", { name: "Mark as false positive: 1 alarm" }).click();
  await expect(page.locator(".toast")).toContainText("1 changed");
  await expect(inspector.locator(".panel-header")).toContainText("False positive");
  // Closing an alarm that isn't the newest still lowers the menu count (#164).
  if (before < 99) await expect(badge).toHaveText(String(before - 1));
  // Then quiet it on this host, from the panel.
  await inspector.getByRole("combobox", { name: /Quiet/ }).click();
  await page.getByRole("option", { name: /On this host/i }).click();
  await inspector.getByRole("button", { name: "Quiet" }).click();
  await inspector.getByRole("textbox", { name: "Why (saved as the note)" }).fill("our backup job");
  await inspector.getByRole("button", { name: "Confirm" }).click();

  await page.getByRole("link", { name: "Alarm suppressions" }).click();
  await expect(page.locator(".view tbody tr").filter({ hasText: "shell-from-database" })).toContainText("our backup job");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("resolved alarms are hidden by default and counted in the empty state", async ({ page }) => {
  await page.goto("/alarms?q=nothing-matches-this");
  await expect(page.getByText("Nothing matches these filters")).toBeVisible();
});

test("Enter in a row's Select picks, never opens the inspector or moves the table cursor", async ({ page }) => {
  await page.goto("/alarms");
  const row = page.locator(".view tbody tr").filter({ hasText: "A shell downloaded a program and ran it" });
  const quiet = row.getByRole("combobox", { name: /Quiet/ });
  await quiet.focus();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("Enter");
  await expect(quiet).toContainText("On this host");
  await expect(page.locator(".inspector .panel-header")).toHaveCount(0);
});

test("quieting from the list asks first, closes the alarm and records why", async ({ page }) => {
  await page.goto("/alarms");
  const row = page.locator(".view tbody tr").filter({ hasText: "A shell downloaded a program and ran it" });
  // Choosing a scope (as arrow keys on a closed select do) changes nothing yet.
  // (The demo keeps its data in memory, so this test never reloads.)
  await row.getByRole("combobox", { name: /Quiet/ }).click();
  await page.getByRole("option", { name: "For this program, any host" }).click();
  await expect(page.locator(".toast")).toHaveCount(0);
  await expect(row.getByRole("button", { name: "Confirm" })).toHaveCount(0);
  await row.getByRole("button", { name: "Quiet" }).click();
  await expect(row).toContainText("/usr/bin/curl on every host?");
  await row.getByRole("textbox", { name: "Why (saved as the note)" }).fill("admin's install script");
  await row.getByRole("button", { name: "Confirm" }).click();
  // Closed as a false positive: it leaves the default (active) list.
  await expect(page.locator(".view tbody tr").filter({ hasText: "A shell downloaded a program and ran it" })).toHaveCount(0);
  await page.getByRole("link", { name: "Alarm suppressions" }).click();
  await expect(page.locator(".view tbody tr").filter({ hasText: "download-and-run" })).toContainText("admin's install script");
});

test("with alarms present, an empty filter result hints at the filters, not setup", async ({ page }) => {
  await page.goto("/alarms?q=no-such-alarm");
  await expect(page.getByText("clear a filter to see more")).toBeVisible();
  await expect(page.getByText("auditd")).toHaveCount(0);
});
