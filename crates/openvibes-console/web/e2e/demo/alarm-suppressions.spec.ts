import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

// Alarm suppressions with approvals (approved screen 14) on the demo:
// the analyst asks, the administrator approves, rejects and removes.
const persona = async (page: Page, name: string) => {
  await page.getByRole("button", { name: "Account" }).click();
  await page.getByRole("menuitemradio", { name, exact: true }).click();
};

const ask = async (page: Page, alarm: string, reason: string) => {
  // From the alarm's page: the list has Suppress… only in its bulk bar (screen 29).
  await page.goto("/alarms");
  await page.locator(".view tbody tr").filter({ hasText: alarm }).first().getByRole("link", { name: alarm }).click();
  await page.locator(".view").getByRole("button", { name: "Suppress…" }).click();
  const form = page.getByRole("dialog", { name: "Suppress alarms like this" });
  await form.getByRole("textbox", { name: "Reason (required)" }).fill(reason);
  await form.getByRole("button", { name: "Request" }).click();
  await expect(page.locator(".toast").last()).toContainText("Requested · waiting for approval");
};

test("requests are withdrawn, approved, rejected and removed, and the menu count follows", async ({ page }) => {
  await page.goto("/settings?tab=general");
  await page.getByRole("switch", { name: "Suppressions need approval" }).click();
  await expect(page.getByText("Saved · recorded in the audit log").first()).toBeVisible();

  await persona(page, "analyst");
  await ask(page, "A database server started a shell", "nightly vacuum script");
  await ask(page, "A shell downloaded a program and ran it", "admin's install script");
  await ask(page, "A web server started a shell", "health check probe");

  // The requester withdraws their own and cannot decide the others.
  await page.goto("/alarm-suppressions");
  await expect(page.getByRole("heading", { name: "Alarm suppressions" })).toBeVisible();
  const waiting = page.locator("#suppressions-waiting");
  await expect(waiting.locator("[data-id]")).toHaveCount(3);
  await expect(waiting.getByRole("button", { name: "Approve" })).toHaveCount(0);
  await waiting.locator("[data-id]").filter({ hasText: "health check probe" }).getByRole("button", { name: "Withdraw" }).click();
  await expect(page.locator(".toast").last()).toContainText("Saved · recorded in the audit log");
  await expect(waiting.locator("[data-id]")).toHaveCount(2);

  // The administrator sees two to decide in the menu.
  await persona(page, "admin");
  await page.goto("/alarm-suppressions");
  const badge = page.locator(".rail .rail__item").filter({ hasText: "Alarm suppressions" }).locator(".rail__count");
  await expect(badge).toHaveText("2");
  await expect(page.locator(".person-card").filter({ hasText: "By status" }).locator("li").first()).toHaveText(/Waiting\s*2/);

  const vacuum = page.locator("[data-id]").filter({ hasText: "nightly vacuum script" });
  await expect(vacuum).toContainText("Would have closed");
  await vacuum.getByRole("button", { name: "Approve" }).click();
  await expect(page.locator("#suppressions-active [data-id]").filter({ hasText: "nightly vacuum script" })).toContainText("Active");
  await expect(badge).toHaveText("1");

  const install = page.locator("#suppressions-waiting [data-id]").filter({ hasText: "admin's install script" });
  await install.getByRole("button", { name: "Reject…" }).click();
  const reject = install.getByRole("button", { name: "Reject", exact: true });
  await expect(reject).toBeDisabled();
  await install.getByRole("textbox", { name: "Reason (required)" }).fill("too broad, limit it to one host");
  await reject.click();
  const rejected = page.locator("#suppressions-rejected [data-id]").filter({ hasText: "admin's install script" });
  await expect(rejected).toContainText("too broad, limit it to one host");
  await expect(badge).toHaveCount(0);
  await expect(page.locator("#suppressions-waiting [data-id]")).toHaveCount(0);

  // Recent changes lists the decisions.
  await expect(page.locator(".person-card").filter({ hasText: "Recent changes" })).toContainText("Rejected a suppression");
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);

  const active = page.locator("#suppressions-active [data-id]").filter({ hasText: "nightly vacuum script" });
  await active.getByRole("button", { name: "Remove…" }).click();
  await active.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator("#suppressions-active [data-id]").filter({ hasText: "nightly vacuum script" })).toHaveCount(0);

  // The requester can ask again, from the rejected row, prefilled.
  await persona(page, "analyst");
  await page.goto("/alarm-suppressions");
  await page.locator("#suppressions-rejected [data-id]").filter({ hasText: "admin's install script" }).getByRole("button", { name: "Ask again…" }).click();
  const form = page.getByRole("dialog", { name: "Suppress alarms like this" });
  await expect(form.getByRole("textbox", { name: "Reason (required)" })).toHaveValue("admin's install script");
  await expect(form).toContainText("/usr/bin/curl");
});
