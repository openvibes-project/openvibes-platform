import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

// The Vulnerabilities list on the demo (approved screen 25): the demo answers
// GET /api/v1/vulnerability-list like vulnerabilities/list_page.rs, over the
// hand-made pairs of demo/vulnSeed.ts among others. The demo keeps its data
// in memory, so a test that changes triage never reloads after the change.
const table = (page: Page) => page.getByRole("table", { name: "Vulnerabilities" });
const rows = (page: Page) => table(page).locator("tbody tr");
const filters = (page: Page) => page.getByRole("group", { name: "Filters" });
const choose = async (page: Page, filter: string, option: RegExp) => {
  await filters(page).getByRole("combobox", { name: filter }).click();
  await page.getByRole("option", { name: option }).click();
};

// The pointer off the rail, which opens while hovered and covers the first columns.
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.mouse.move(900, 500);
});

test("filters by Signals and Package, and a reload keeps both", async ({ page }) => {
  await page.goto("/vulnerabilities");
  await expect(rows(page).first()).toBeVisible();
  await expect(page.locator(".summary-line")).toContainText(/\d+ open on \d+ hosts? · \d+ known exploited · \d+ with a due date · \d+ without a fix · \d+ unassigned/);
  await choose(page, "Signals", /^Known exploited/);
  await expect(filters(page)).toContainText("Signals: Known exploited");
  await choose(page, "Package", /^openssl/);
  await expect(filters(page)).toContainText("Package: openssl");
  await expect(page).toHaveURL(/[?&]signal=exploited/);
  await expect(page).toHaveURL(/[?&]package=openssl/);
  const check = async () => {
    await expect(rows(page).filter({ hasText: "CVE-2026-20037" })).toHaveCount(1);
    for (const text of await rows(page).allTextContents()) {
      expect(text).toContain("Exploited");
      expect(text).toContain("openssl");
    }
  };
  await check();
  await page.reload();
  await expect(filters(page)).toContainText("Signals: Known exploited");
  await expect(filters(page)).toContainText("Package: openssl");
  await check();
});

test("Lower confidence shows only the lower-confidence matches", async ({ page }) => {
  await page.goto("/vulnerabilities");
  await expect(rows(page).first()).toBeVisible();
  await expect(rows(page).filter({ hasText: "CVE-2026-20112" })).toHaveCount(0);
  await choose(page, "Signals", /^Lower confidence/);
  await expect(rows(page).filter({ hasText: "CVE-2026-20112" })).toHaveCount(1);
  for (const text of await rows(page).allTextContents()) expect(text).toContain("Lower confidence");
});

test("a saved view comes back after Clear all", async ({ page }) => {
  await page.goto("/vulnerabilities?state=all&signal=nofix");
  await expect(rows(page).first()).toBeVisible();
  await page.getByRole("button", { name: "Save view" }).click();
  await page.getByRole("textbox", { name: "View name" }).fill("No fix, any state");
  await page.keyboard.press("Enter");
  await expect(page.locator(".toast").last()).toContainText("View “No fix, any state” saved");
  await page.getByRole("button", { name: "Clear all" }).click();
  await expect(page).toHaveURL(/\/vulnerabilities$/);
  await page.getByRole("group", { name: "Saved views" }).getByRole("button", { name: "No fix, any state", exact: true }).click();
  await expect(filters(page)).toContainText("State: All states");
  await expect(filters(page)).toContainText("Signals: No fix yet");
  for (const text of await rows(page).allTextContents()) expect(text).toContain("no fix yet");
});

test("a hidden column stays hidden after a reload; Severity and Advisory can't be hidden", async ({ page }) => {
  await page.goto("/vulnerabilities");
  await expect(table(page).getByRole("columnheader", { name: "EPSS" })).toBeVisible();
  await page.getByRole("button", { name: "Columns" }).click();
  await expect(page.getByRole("checkbox", { name: "Severity" })).toBeDisabled();
  await expect(page.getByRole("checkbox", { name: "Advisory" })).toBeDisabled();
  await page.getByRole("checkbox", { name: "EPSS" }).uncheck();
  await expect(table(page).getByRole("columnheader", { name: "EPSS" })).toHaveCount(0);
  await page.reload();
  await expect(rows(page).first()).toBeVisible();
  await expect(table(page).getByRole("columnheader", { name: "EPSS" })).toHaveCount(0);
});

test("the CVE is a real link to its page, and the row shows screen 25's cells", async ({ page }) => {
  await page.goto("/vulnerabilities?q=CVE-2026-20037");
  const row = rows(page).filter({ hasText: "CVE-2026-20037" });
  await expect(row).toContainText("fixed in 2 versions");
  await expect(row).toContainText("2 people");
  await expect(row.getByRole("progressbar", { name: "4 open of 6 hosts" })).toBeVisible();
  await expect(row.locator(".due--late")).toBeVisible();
  await expect(row.getByRole("link", { name: "openssl security update (CVE-2026-20037)", exact: true })).toHaveAttribute("href", "/vulnerabilities/CVE-2026-20037");
});

test("bulk Set state names the open hosts and the other CVEs, and changes only open ones; there is no Reopen", async ({ page }) => {
  await page.goto("/vulnerabilities?q=CVE-2026-20037");
  await rows(page).filter({ hasText: "CVE-2026-20037" }).getByRole("checkbox", { name: "Select row" }).check();
  const bar = page.getByRole("region", { name: "Bulk actions" });
  await expect(bar).toContainText("1 selected");
  await expect(bar.getByRole("button", { name: /Reopen/ })).toHaveCount(0);
  await bar.getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^Mitigate…/ }).click();
  const dialog = page.getByRole("dialog", { name: "Mitigate" });
  await expect(dialog).toContainText("Changes up to 4 open hosts. Hosts without a fix yet are left as they are");
  await expect(dialog).toContainText("also cover CVE-2026-20051");
  await dialog.getByRole("textbox", { name: "Why (required)" }).fill("patched by hand");
  await dialog.getByRole("button", { name: "Mitigate 1 vulnerability" }).click();
  await expect(page.locator(".toast").last()).toContainText("4 changed; 1 skipped (1 not open)");
  // No open pair left: it leaves the default (open) list without a reload.
  await expect(page.getByText("No advisory matches these filters")).toBeVisible();
});

test("bulk Assign asks first, saying how many open hosts it reaches", async ({ page }) => {
  await page.goto("/vulnerabilities?q=CVE-2026-20042");
  await rows(page).filter({ hasText: "CVE-2026-20042" }).getByRole("checkbox", { name: "Select row" }).check();
  const bar = page.getByRole("region", { name: "Bulk actions" });
  await bar.getByRole("combobox", { name: "Assign vulnerability" }).click();
  await page.getByRole("option", { name: /^Unassigned/ }).click();
  const dialog = page.getByRole("dialog", { name: "Unassign" });
  await expect(dialog).toContainText("Changes up to 2 open hosts");
  await dialog.getByRole("button", { name: "Unassign 1 vulnerability" }).click();
  await expect(page.locator(".toast").last()).toContainText("2 changed");
  await expect(rows(page).filter({ hasText: "CVE-2026-20042" })).toContainText("Unassigned");
});

test("old_vulnerability_urls_keep_their_filters: old flags and a view saved in this browser come over", async ({ page }) => {
  await page.evaluate(() => localStorage.setItem("openvibes.v2.views./vulnerabilities",
    JSON.stringify([{ name: "Old reboots", query: "state=all&reboot=true&sort=title&dir=asc" }])));
  await page.goto("/vulnerabilities?exploited=true&nofix=true");
  await expect(page).toHaveURL(/\/vulnerabilities\?signal=exploited$/);
  await expect(filters(page)).toContainText("Signals: Known exploited");
  // In place: Back leaves the list, it does not land on the old address.
  await page.goBack();
  await expect(page).not.toHaveURL(/exploited=true/);
  await page.goto("/vulnerabilities?lowconf=true");
  await expect(page).toHaveURL(/\/vulnerabilities\?signal=lowconf$/);
  await page.getByRole("group", { name: "Saved views" }).getByRole("button", { name: "Old reboots", exact: true }).click();
  await expect(filters(page)).toContainText("Signals: Reboot needed");
  await expect(filters(page)).toContainText("State: All states");
  await expect(page).not.toHaveURL(/sort=/);
  expect(await page.evaluate(() => localStorage.getItem("openvibes.v2.views./vulnerabilities"))).toBeNull();
});

test("axe finds nothing on the list, filtered, selected or not", async ({ page }) => {
  await page.goto("/vulnerabilities");
  await expect(rows(page).first()).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.goto("/vulnerabilities?state=all&signal=due30");
  await expect(rows(page).first()).toBeVisible();
  await rows(page).first().getByRole("checkbox", { name: "Select row" }).check();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
});
