import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

// An alarm's page (approved screen 30) on the demo: the demo answers
// GET /api/v1/alarms/{id}/summary like alarms/summary.rs. Alarm 9000 is
// "A web server started a shell" (sh -c id; uname -a, 3 starts) with two
// siblings: 9008, healthcheck ×12 (the usual one), and 9009, cat /etc/passwd ×1.
const heading = (page: Page) => page.getByRole("heading", { level: 1 });
const card = (page: Page, title: string | RegExp) => page.locator(".person-card").filter({ has: page.getByRole("heading", { name: title, exact: true }) });
const commands = (page: Page) => card(page, /^Commands seen/).locator("tbody tr");
/** The evidence and the history have loaded: nothing moves under a popover any more. */
const settled = async (page: Page) => {
  await expect(page.locator(".detection-verdict")).toBeVisible();
  await expect(card(page, "History").getByText("No triage changes yet")).toBeVisible();
};

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(heading(page)).toContainText("Alex");
});

test("old_alarm_links_open_the_page: an old alarm panel link lands on the page, and Back skips the dead URL", async ({ page }) => {
  await page.goto("/alarms");
  await expect(heading(page)).toHaveText("Alarms");
  await page.goto("/?open=alarm%3A9000");
  await expect(page).toHaveURL(/\/alarms\/9000$/);
  await expect(heading(page)).toHaveText("A web server started a shell");
  await expect(page.locator(".inspector")).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/\/alarms$/);
  // A link to an alarm elsewhere (the host page's Open alarms) opens the page too.
  await page.goto("/hosts/agent-00001");
  const link = page.locator(".person-card", { has: page.getByRole("heading", { name: /^Open alarms/ }) }).locator("tbody a").first();
  await expect(link).toHaveAttribute("href", /\/alarms\/\d+$/);
  await link.click();
  await expect(page).toHaveURL(/\/alarms\/\d+$/);
  await expect(page.locator(".inspector")).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/\/hosts\/agent-00001$/);
});

test("suppress_this_command_uses_that_line: the usual command's Suppress this command… suppresses that sibling", async ({ page }) => {
  await page.goto("/alarms/9000");
  await expect(commands(page)).toHaveCount(3);
  const usual = commands(page).first();
  await expect(usual).toContainText("/usr/local/bin/healthcheck");
  await expect(commands(page).getByRole("button", { name: "Suppress this command…" })).toHaveCount(1);
  await usual.getByRole("button", { name: "Suppress this command…" }).click();
  const form = page.getByRole("dialog", { name: "Suppress alarms like this" });
  await expect(form.getByRole("radio", { name: "This exact command" })).toBeChecked();
  await expect(form).toContainText("/usr/bin/sh sh -c /usr/local/bin/healthcheck");
  await form.getByRole("textbox", { name: "Reason (required)" }).fill("load balancer health check");
  await form.getByRole("button", { name: "Suppress", exact: true }).click();
  await expect(page.locator(".toast").last()).toContainText("Suppressed · recorded in the audit log");
  // The request's alarm_id is the sibling's: the suppression opens 9008, not 9000.
  await page.goto("/alarm-suppressions");
  const row = page.locator("#suppressions-active [data-id]").filter({ hasText: "load balancer health check" });
  await expect(row.getByRole("link", { name: "Open alarm" })).toHaveAttribute("href", /\/alarms\/9008$/);
});

test("with a request for the usual command waiting, Suppress this command… says so instead of a second form", async ({ page }) => {
  await page.goto("/settings?tab=general");
  await page.getByRole("switch", { name: "Suppressions need approval" }).click();
  await expect(page.getByText("Saved · recorded in the audit log").first()).toBeVisible();
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name: "analyst", exact: true }).click();
  await page.goto("/alarms/9000");
  const press = () => commands(page).first().getByRole("button", { name: "Suppress this command…" }).click();
  await press();
  const form = page.getByRole("dialog", { name: "Suppress alarms like this" });
  await form.getByRole("textbox", { name: "Reason (required)" }).fill("load balancer health check");
  await form.getByRole("button", { name: "Request" }).click();
  await expect(page.locator(".toast").last()).toContainText("Requested · waiting for approval");
  await press();
  await expect(commands(page).first()).toContainText("A request for this command is waiting for approval");
  await expect(form).toHaveCount(0);
});

test("Set state from the header closes the alarm, and Reopen opens it again", async ({ page }) => {
  await page.goto("/alarms/9000");
  await page.locator(".person-page__actions").getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^False positive/ }).click();
  const dialog = page.getByRole("dialog", { name: "False positive" });
  await dialog.getByRole("textbox", { name: "Why (required)" }).fill("our own probe");
  await dialog.getByRole("button", { name: "Mark as false positive: 1 alarm" }).click();
  await expect(page.locator(".toast")).toContainText("1 changed");
  await expect(page.locator(".person-page__head")).toContainText("False positive");
  await expect(card(page, "Details")).toContainText("our own probe");
  await card(page, "Details").getByRole("button", { name: "Reopen" }).click();
  await expect(page.locator(".person-page__head")).toContainText("Open");
});

test("Add to case on a command seen once puts that sibling in a case", async ({ page }) => {
  await page.goto("/alarms/9000");
  await settled(page);
  const once = commands(page).filter({ hasText: "cat /etc/passwd" });
  await expect(once).toHaveClass(/cmd-once/);
  await expect(once).toContainText("Seen once");
  await once.getByRole("button", { name: "Add sh -c cat /etc/passwd to a case" }).click();
  const menu = page.getByRole("dialog", { name: /Add alarm to a case/ });
  await menu.getByRole("button", { name: "New case…" }).click();
  await menu.getByLabel("Title").fill("Someone read passwd");
  await menu.getByRole("button", { name: "Open case" }).click();
  await expect(page.locator(".toast")).toContainText("Opened C-111");
  await page.keyboard.press("Escape");
  await expect(once).toContainText("C-111");
});

test("the last 24 hours draw as bars, with the same numbers in a table", async ({ page }) => {
  await page.goto("/alarms/9000");
  const timeline = card(page, "Last 24 hours");
  await expect(timeline.locator("svg rect")).toHaveCount(24);
  await expect(timeline.locator("table tbody tr")).toHaveCount(24);
  await page.getByRole("link", { name: /^Different commands: 3$/ }).click();
  await expect(page).toHaveURL(/\/alarms\/9000#commands$/);
});

for (const scheme of ["light", "dark"] as const) {
  test(`the page passes axe (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto("/alarms/9000");
    await expect(heading(page)).toHaveText("A web server started a shell");
    await settled(page);
    await page.mouse.move(900, 500);
    await page.waitForTimeout(400);
    const result = await new AxeBuilder({ page }).analyze();
    expect(result.violations.flatMap((v) => v.nodes.map((n) => `${v.id}: ${n.target.join(" ")} ${n.any[0]?.message ?? ""}`))).toEqual([]);
  });
}
