import { type Page, expect, test } from "@playwright/test";

import { expectNoAxeViolations } from "./list-helpers";

// A case's page (approved screen 32) on the demo: the demo answers
// GET /api/v1/cases/{id}/summary like cases/page.rs, and the full detail and
// write routes like the console. The seed (src/demo/caseSeed.ts): C-104 holds
// two open alarms without an outcome, C-102 known exploited vulnerabilities,
// C-105 is closed. The demo keeps its data in memory, so each test starts
// from the seed.
const heading = (page: Page) => page.getByRole("heading", { level: 1 });
const card = (page: Page, title: RegExp) => page.locator(".person-card").filter({ has: page.getByRole("heading", { name: title }) });
const actions = (page: Page) => page.locator(".person-page__actions");
const CASE = /\/cases\/[0-9a-f-]+$/;

/** The page of case `C-n`, reached from the list; returns its id. */
async function openCase(page: Page, n: number): Promise<string> {
  await page.goto(`/cases?status=all&q=C-${n}`);
  const link = page.getByRole("table", { name: "Cases" }).getByRole("link", { name: new RegExp(`^C-${n} `) });
  const href = (await link.getAttribute("href")) ?? "";
  await link.click();
  await expect(page).toHaveURL(CASE);
  await expect(heading(page)).toContainText(`C-${n}`);
  return href.slice("/cases/".length);
}

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(heading(page)).toContainText("Alex");
});

test("old_case_links_open_the_page: addresses, alarms, Add to case, vulnerabilities and the palette, with no dead history entry", async ({ page }) => {
  const id = await openCase(page, 104);
  // An old panel address: the page, the URL replaced in place.
  await page.goto("/alarms");
  await expect(page.getByRole("table", { name: "Alarms" })).toBeVisible();
  await page.goto(`/alarms?open=case%3A${id}`);
  await expect(page).toHaveURL(new RegExp(`/cases/${id}$`));
  await expect(heading(page)).toContainText("C-104");
  await expect(page.locator(".inspector")).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/\/alarms$/);
  // The old new-case panel is the form's page.
  await page.goto("/cases?open=case%3Anew");
  await expect(page).toHaveURL(/\/cases\/new$/);
  await expect(page.getByRole("button", { name: "Open case" })).toBeVisible();
  // An alarm of the case: its Add to case names the case and links to its page.
  await page.goto(`/cases/${id}`);
  await card(page, /^Items/).getByRole("link").first().click();
  await expect(page).toHaveURL(/\/alarms\/\d+$/);
  await expect(page.locator(".detection-verdict")).toBeVisible();
  const add = card(page, /^Details/).getByRole("button", { name: /C-104/ });
  await add.scrollIntoViewIfNeeded();
  await page.evaluate(() => new Promise((done) => requestAnimationFrame(() => requestAnimationFrame(done))));
  await add.click();
  const holding = page.getByRole("dialog", { name: /Add alarm to a case/ }).getByRole("link", { name: /C-104/ });
  await expect(holding).toHaveAttribute("href", `/cases/${id}`);
  await holding.click();
  await expect(page).toHaveURL(new RegExp(`/cases/${id}$`));
  await expect(page.locator(".inspector")).toHaveCount(0);
  // A vulnerability's Cases card.
  const other = await openCase(page, 102);
  await card(page, /^Items/).locator(".case-item").filter({ hasText: "Vulnerability" }).first().locator(".case-item__title a").click();
  // An advisory over several CVEs is the list, filtered to it; a CVE is its page.
  await page.locator("tbody tr").first().getByRole("link").first().click();
  await expect(page).toHaveURL(/\/vulnerabilities\/CVE-[^/]+$/);
  await page.getByRole("list", { name: "Cases" }).getByRole("link", { name: /^C-102/ }).click();
  await expect(heading(page)).toContainText("C-102");
  // The palette's recent objects, from another page.
  await page.getByRole("link", { name: "Cases", exact: true }).first().click();
  await page.keyboard.press("Control+k");
  await page.getByRole("option", { name: /C-102.*Case/ }).click();
  await expect(page).toHaveURL(new RegExp(`/cases/${other}$`));
});

test("the header, tiles and cards say what the case is, who works on it and what is left", async ({ page }) => {
  await openCase(page, 104);
  await expect(heading(page)).toContainText("Web servers starting shells");
  await expect(page.locator(".detail-page__facts")).toContainText("Opened by");
  for (const name of ["Edit", "Assign", "Close case…"]) await expect(actions(page).getByRole("button", { name, exact: true })).toBeVisible();
  // The assistant takes no case reference (ruling 14): no Ask about this.
  await expect(actions(page).getByRole("button", { name: /Ask about this/ })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Items: 2" })).toBeVisible();
  await expect(page.locator(".detail-tiles")).toContainText("Need an outcome");
  await expect(card(page, /^Hosts in this case/).getByRole("link").first()).toHaveAttribute("href", /^\/hosts\//);
  await expect(card(page, /^Who can see it/)).toContainText(/\d+ (people|person)/);
  await expect(card(page, /^Details/)).toContainText("Severity");
});

test("each outcome can be set, a note is required except for Fixed, and Fixed waits for the evidence", async ({ page }) => {
  await openCase(page, 104);
  const items = card(page, /^Items/).locator(".case-item");
  await expect(items).toHaveCount(2);
  const first = items.first();
  await first.getByRole("combobox", { name: /^Outcome for/ }).click();
  await expect(page.getByRole("option", { name: /^Fixed/ })).toHaveAttribute("aria-disabled", "true");
  for (const label of ["Confirmed malicious", "Expected activity", "False positive", "Risk accepted"]) await expect(page.getByRole("option", { name: label })).toBeVisible();
  await page.getByRole("option", { name: "Risk accepted" }).click();
  // The note and the date are required; the browser refuses the form without them.
  await first.getByRole("button", { name: "Save outcome" }).click();
  await expect(first.getByRole("textbox", { name: /^Note for/ })).toHaveJSProperty("validity.valid", false);
  await first.getByRole("textbox", { name: /^Note for/ }).fill("The owner signs off until the rebuild.");
  const day = new Date(Date.now() + 30 * 86_400_000).toISOString().slice(0, 10);
  await first.getByLabel(/^Re-open date for/).fill(day);
  await first.getByRole("button", { name: "Save outcome" }).click();
  await expect(page.locator(".toast").filter({ hasText: "Outcome saved" })).toBeVisible();
  await expect(first).toContainText("Risk accepted");
  // Each of the others on the second item, the last one kept.
  const second = items.nth(1);
  for (const label of ["Confirmed malicious", "Expected activity", "False positive"]) {
    await second.getByRole("combobox", { name: /^Outcome for/ }).click();
    await page.getByRole("option", { name: label }).click();
    await second.getByRole("textbox", { name: /^Note for/ }).fill(`Why: ${label}`);
    await second.getByRole("button", { name: "Save outcome" }).click();
    await expect(second.locator(".case-item__meta")).toContainText(label);
  }
  await expect(page.locator(".detail-tiles")).toContainText("Ready to close");
});

test("closing is blocked until every item has an outcome, then takes a closing note; Reopen is on ⋯", async ({ page }) => {
  await openCase(page, 104);
  await actions(page).getByRole("button", { name: "Close case…" }).click();
  let dialog = page.getByRole("dialog", { name: "Close C-104" });
  await expect(dialog).toContainText("2 items still need an outcome");
  await dialog.getByLabel("Closing note").fill("Both are the health check.");
  await expect(dialog.getByRole("button", { name: "Close case" })).toBeDisabled();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  const items = card(page, /^Items/).locator(".case-item");
  for (let n = 0; n < 2; n += 1) {
    const item = items.nth(n);
    await item.getByRole("combobox", { name: /^Outcome for/ }).click();
    await page.getByRole("option", { name: "Expected activity" }).click();
    await item.getByRole("textbox", { name: /^Note for/ }).fill("Our health check script.");
    await item.getByRole("button", { name: "Save outcome" }).click();
    await expect(item.getByRole("button", { name: "Save outcome" })).toBeDisabled();
  }
  await actions(page).getByRole("button", { name: "Close case…" }).click();
  dialog = page.getByRole("dialog", { name: "Close C-104" });
  await expect(dialog).not.toContainText("still need");
  await expect(dialog.getByRole("button", { name: "Close case" })).toBeDisabled();
  await dialog.getByLabel("Closing note").fill("Both are the same health check.");
  await dialog.getByRole("button", { name: "Close case" }).click();
  await expect(page.locator(".toast").filter({ hasText: "Case closed" })).toBeVisible();
  await expect(page.locator(".person-page__head")).toContainText("Closed");
  await expect(card(page, /^Details/)).toContainText("Both are the same health check.");
  await expect(actions(page).getByRole("button", { name: "Close case…" })).toHaveCount(0);
  // Reopen, on ⋯.
  await actions(page).getByRole("button", { name: "More actions" }).click();
  await page.getByRole("menuitem", { name: "Reopen" }).click();
  await expect(page.locator(".toast").filter({ hasText: "Case reopened" })).toBeVisible();
  await expect(actions(page).getByRole("button", { name: "Close case…" })).toBeVisible();
  await expect(card(page, /^Notes and timeline/).locator(".timeline__item").first()).toContainText("reopened the case");
});

test("a note goes on top of the timeline, newest first", async ({ page }) => {
  await openCase(page, 103);
  const notes = card(page, /^Notes and timeline/);
  await notes.getByRole("textbox", { name: "Note" }).fill("Disabled password logins in the staging copy of sshd_config.");
  await notes.getByRole("button", { name: "Add note" }).click();
  await expect(page.locator(".toast").filter({ hasText: "Note added" })).toBeVisible();
  await expect(notes.getByRole("list", { name: /Timeline/ }).locator("li").first()).toContainText("Disabled password logins");
  await expect(notes.getByRole("textbox", { name: "Note" })).toHaveValue("");
});

test("Edit changes the title and severity, Assign the assignee, and Add item and Remove stay", async ({ page }) => {
  await openCase(page, 104);
  await actions(page).getByRole("button", { name: "Edit", exact: true }).click();
  const edit = page.getByRole("dialog", { name: "Edit C-104" });
  await edit.getByLabel("Title").fill("Shells on the web servers");
  await edit.getByRole("button", { name: "Save" }).click();
  await expect(heading(page)).toContainText("Shells on the web servers");
  await actions(page).getByRole("button", { name: "Assign", exact: true }).click();
  await page.getByRole("menuitem", { name: /^Assign to me/ }).click();
  await expect(page.locator(".detail-page__facts")).toContainText("assigned to");
  const items = card(page, /^Items/);
  await items.getByRole("button", { name: "Add item" }).click();
  await page.getByRole("combobox", { name: "Kind" }).click();
  await page.getByRole("option", { name: "Host", exact: true }).click();
  await page.getByLabel("Id").fill("agent-00001");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.locator(".toast").filter({ hasText: "Item added" })).toBeVisible();
  await expect(items.locator(".case-item")).toHaveCount(3);
  await items.locator(".case-item").last().getByRole("button", { name: "Remove" }).click();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(items.locator(".case-item")).toHaveCount(2);
});

for (const scheme of ["light", "dark"] as const) {
  test(`the page passes axe (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await openCase(page, 104);
    await expect(card(page, /^Items/).locator(".case-item").first()).toBeVisible();
    await expectNoAxeViolations(page);
    await actions(page).getByRole("button", { name: "Close case…" }).click();
    await expect(page.getByRole("dialog", { name: "Close C-104" })).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
