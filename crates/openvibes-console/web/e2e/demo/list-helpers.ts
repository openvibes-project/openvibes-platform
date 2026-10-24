import AxeBuilder from "@axe-core/playwright";
import { type Locator, type Page, expect, test } from "@playwright/test";

// Steps the demo's list specs (Vulnerabilities, Compliance) share.

/** The list's table, rows and Filters group, and the filter-chip chooser. */
export const listParts = (tableName: string) => {
  const table = (page: Page) => page.getByRole("table", { name: tableName });
  const rows = (page: Page) => table(page).locator("tbody tr");
  const filters = (page: Page) => page.getByRole("group", { name: "Filters" });
  const choose = async (page: Page, filter: string, option: RegExp) => {
    await filters(page).getByRole("combobox", { name: filter }).click();
    await page.getByRole("option", { name: option }).click();
  };
  return { table, rows, filters, choose };
};

/** The pointer off the rail, which opens while hovered and covers the first columns. */
export const pointerOffRail = () =>
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page.mouse.move(900, 500);
  });

export const expectChips = async (filters: Locator, chips: string[]) => {
  for (const chip of chips) await expect(filters).toContainText(chip);
};

/** Save the open view under `name`, press Clear all, then pick the view from Saved views. */
export const saveClearRestore = async (page: Page, name: string, cleared: RegExp) => {
  await page.getByRole("button", { name: "Save view" }).click();
  await page.getByRole("textbox", { name: "View name" }).fill(name);
  await page.keyboard.press("Enter");
  await expect(page.locator(".toast").last()).toContainText(`View “${name}” saved`);
  await page.getByRole("button", { name: "Clear all" }).click();
  await expect(page).toHaveURL(cleared);
  await page.getByRole("group", { name: "Saved views" }).getByRole("button", { name, exact: true }).click();
};

/** Hide `column` from the Columns menu, after checking the locked ones cannot be hidden, and reload. */
export const hideColumnAcrossReload = async (page: Page, table: ReturnType<typeof listParts>["table"], rows: ReturnType<typeof listParts>["rows"], column: string, locked: string[]) => {
  await expect(table(page).getByRole("columnheader", { name: column })).toBeVisible();
  await page.getByRole("button", { name: "Columns" }).click();
  for (const name of locked) await expect(page.getByRole("checkbox", { name })).toBeDisabled();
  await page.getByRole("checkbox", { name: column }).uncheck();
  await expect(table(page).getByRole("columnheader", { name: column })).toHaveCount(0);
  await page.reload();
  await expect(rows(page).first()).toBeVisible();
  await expect(table(page).getByRole("columnheader", { name: column })).toHaveCount(0);
};

/** Tick the row of `text`, and open the bulk bar's Set state > Mitigate… dialog. */
export const openBulkMitigate = async (page: Page, rows: ReturnType<typeof listParts>["rows"], text: string) => {
  await rows(page).filter({ hasText: text }).getByRole("checkbox", { name: "Select row" }).check();
  const bar = page.getByRole("region", { name: "Bulk actions" });
  await expect(bar).toContainText("1 selected");
  await expect(bar.getByRole("button", { name: /Reopen/ })).toHaveCount(0);
  await bar.getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^Mitigate…/ }).click();
  return page.getByRole("dialog", { name: "Mitigate" });
};

export const expectNoAxeViolations = async (page: Page) => expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);

/** The list passes axe as it opens, then filtered with the first row selected. */
export const axeListAndFiltered = async (page: Page, rows: ReturnType<typeof listParts>["rows"], list: string, filtered: string) => {
  await page.goto(list);
  await expect(rows(page).first()).toBeVisible();
  await expectNoAxeViolations(page);
  await page.goto(filtered);
  await expect(rows(page).first()).toBeVisible();
  await rows(page).first().getByRole("checkbox", { name: "Select row" }).check();
  await expectNoAxeViolations(page);
};

/** A check's page (demo and live): its cards, the Hosts card's rows, and its Hosts-by-state segments. */
export const hostsCardParts = () => {
  const card = (page: Page, title: string | RegExp) => page.locator(".person-card").filter({ has: page.getByRole("heading", { name: title }) });
  const hosts = (page: Page) => card(page, /^Hosts/).getByRole("table", { name: "Hosts", exact: true }).locator("tbody > tr");
  const segments = (page: Page) => page.getByRole("radiogroup", { name: "Hosts by state" });
  const pickSegment = (page: Page, name: RegExp) => segments(page).getByRole("radio", { name }).click();
  return { card, hosts, segments, pickSegment };
};

/** Press a Set state button, choose Mitigate and return the dialog it opens. */
export const openMitigate = async (page: Page, setState: Locator) => {
  await setState.click();
  await page.getByRole("menuitem", { name: /^Mitigate/ }).click();
  return page.getByRole("dialog", { name: "Mitigate" });
};

/** Give the Mitigate dialog its reason and press the button named `confirm`. */
export const confirmMitigate = async (dialog: Locator, reason: string, confirm: string | RegExp) => {
  await dialog.getByRole("textbox").fill(reason);
  await dialog.getByRole("button", { name: confirm }).click();
};
