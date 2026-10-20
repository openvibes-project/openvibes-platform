import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Settings › General on the demo (approved screen 11).
test("an administrator switches approval on, and it stays on", async ({ page }) => {
  await page.goto("/settings?tab=general");
  const toggle = page.getByRole("switch", { name: "Suppressions need approval" });
  await expect(toggle).toHaveAttribute("aria-checked", "false");
  await toggle.click();
  await expect(page.getByText("Saved · recorded in the audit log").first()).toBeVisible();
  await expect(toggle).toHaveAttribute("aria-checked", "true");
  await expect(page.getByText(/Approvers: people whose role holds Approve suppressions/)).toBeVisible();
  await page.reload();
  await expect(page.getByRole("switch", { name: "Suppressions need approval" })).toHaveAttribute("aria-checked", "true");
  await expect(page.getByText("Changed a setting").first()).toBeVisible();
});

test("a number outside the range is refused with the server's words", async ({ page }) => {
  await page.goto("/settings?tab=general");
  const days = page.getByRole("spinbutton", { name: "Remove inactive single sign-on users" });
  await days.fill("0");
  await days.press("Enter");
  await expect(page.getByRole("alert").filter({ hasText: "Use a whole number from 1 to 3650" })).toBeVisible();
  await expect(days).toHaveValue("0");
});

test("the page has no accessibility violations", async ({ page }) => {
  await page.goto("/settings?tab=general");
  await expect(page.getByRole("heading", { level: 1, name: "General" })).toBeVisible();
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});
