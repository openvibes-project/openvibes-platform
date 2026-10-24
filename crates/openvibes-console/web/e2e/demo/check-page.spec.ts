import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

// A check's page (approved screen 28) on the demo: the demo answers
// GET /api/v1/compliance/checks/{set}/{rule}/summary and /hosts like
// compliance/page.rs. hardening-linux-l1/harden.ssh.permit_root_login
// (demo/checkSeed.ts) fails open on hosts 1 and 2, mitigated on 4, accepted
// on 5 and false positive on 7; the other hardening hosts pass. The demo keeps
// its data in memory, so a test that changes triage never reloads.
const ROOT = "harden.ssh.permit_root_login";
const PAGE = `/compliance/hardening-linux-l1/${ROOT}`;
const SSH = /\/compliance\/baseline\/port\.ssh\.exposed$/;
const heading = (page: Page) => page.getByRole("heading", { level: 1 });
const card = (page: Page, title: string | RegExp) => page.locator(".person-card").filter({ has: page.getByRole("heading", { name: title }) });
const hosts = (page: Page) => card(page, /^Hosts/).getByRole("table", { name: "Hosts", exact: true }).locator("tbody > tr");
const segments = (page: Page) => page.getByRole("radiogroup", { name: "Hosts by state" });

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(heading(page)).toContainText("Alex");
  await page.mouse.move(900, 500);
});

test("old_finding_links_open_the_page: addresses, dashboards, the host page, cases, the audit log and the palette, with no dead history entry", async ({ page }) => {
  // An old address: the page, the URL replaced in place.
  await page.goto("/compliance");
  await expect(page.getByRole("table", { name: "Compliance" })).toBeVisible();
  await page.goto("/compliance?open=finding%3Abaseline%2Fport.ssh.exposed");
  await expect(page).toHaveURL(SSH);
  await expect(heading(page)).toBeVisible();
  await expect(page.locator(".inspector")).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/\/compliance$/);
  // The dashboard's attention rows.
  await page.goto("/");
  const row = page.locator('.attention__row[href^="/compliance/"]').first();
  await expect(row).toBeVisible();
  await row.click();
  await expect(page).toHaveURL(/\/compliance\/[^/?]+\/[^/?]+$/);
  await expect(card(page, /^Hosts/)).toBeVisible();
  await page.goBack();
  await expect(page.locator(".attention__row").first()).toBeVisible();
  // The host page's Compliance failing card.
  await page.goto("/hosts/agent-00001");
  const link = card(page, /^Compliance failing/).locator("tbody a").first();
  await expect(link).toHaveAttribute("href", /^\/compliance\/[^?]+$/);
  await link.click();
  await expect(page).toHaveURL(/\/compliance\/[^/?]+\/[^/?]+$/);
  await expect(card(page, /^Hosts/)).toBeVisible();
  // A case's finding item.
  await page.goto("/cases");
  await page.getByRole("table", { name: "Cases" }).locator("tbody tr").filter({ hasText: "SSH open to the network" }).locator("td").nth(1).click();
  const item = page.locator(".inspector").getByRole("list", { name: "Items" }).locator('a[href^="/compliance/"]');
  await expect(item).toHaveCount(1);
  await item.click();
  await expect(page).toHaveURL(SSH);
  await expect(page.locator(".inspector")).toHaveCount(0);
  // The audit log's finding.triage event.
  await page.goto("/audit");
  await page.locator(".view tbody tr").filter({ hasText: "finding.triage" }).first().locator("td").nth(1).click();
  await page.locator(".inspector").getByRole("link", { name: "baseline/port.ssh.exposed" }).click();
  await expect(page).toHaveURL(SSH);
  // The palette.
  await page.keyboard.press("Control+k");
  await page.getByRole("combobox", { name: "Search" }).fill(ROOT);
  await page.getByRole("option", { name: new RegExp(ROOT.replace(/\./g, "\\.")) }).first().click();
  await expect(page).toHaveURL(new RegExp(`${PAGE.replace(/\./g, "\\.")}$`));
  await expect(heading(page)).toHaveText("SSH allows root to log in with a password");
});

test("the header, tiles and cards say what the check is and where it fails", async ({ page }) => {
  await page.goto(PAGE);
  await expect(heading(page)).toHaveText("SSH allows root to log in with a password");
  await expect(page.locator(".detail-page__facts")).toContainText(new RegExp(`${ROOT.replace(/\./g, "\\.")} · hardening-linux-l1 v\\d+ · SSH · failing on 5 of \\d+ hosts checked · assigned to Sam Analyst`));
  await expect(page.locator(".detail-tiles").getByRole("link", { name: /^Failing on, of \d+ hosts checked: 5$/ })).toBeVisible();
  await expect(page.locator(".detail-tiles")).toContainText("Last 14 days");
  await expect(card(page, "Why it matters")).toBeVisible();
  await expect(card(page, "How to fix")).toContainText("No fix text yet");
  await expect(card(page, "History")).toContainText("started failing");
});

test("switches the Hosts segments, and an unknown one reads as All", async ({ page }) => {
  await page.goto(PAGE);
  await expect(hosts(page)).not.toHaveCount(0);
  await segments(page).getByRole("radio", { name: /^Failing/ }).click();
  await expect(page).toHaveURL(/[?&]segment=failing/);
  await expect(hosts(page)).toHaveCount(5);
  for (const text of await hosts(page).allTextContents()) expect(text).not.toContain("Passing");
  await segments(page).getByRole("radio", { name: /^Passing/ }).click();
  await expect(page).toHaveURL(/[?&]segment=passing/);
  for (const text of await hosts(page).allTextContents()) expect(text).toContain("Passing");
  await page.goto(`${PAGE}?segment=bogus`);
  await expect(segments(page).getByRole("radio", { name: /^All/ })).toHaveAttribute("aria-checked", "true");
});

test("passing rows have no checkbox; failing rows do, and open their evidence", async ({ page }) => {
  await page.goto(`${PAGE}?segment=passing`);
  await expect(hosts(page).first()).toContainText("Passing");
  await expect(hosts(page).getByRole("checkbox")).toHaveCount(0);
  await expect(hosts(page).getByRole("button", { name: "View evidence" })).toHaveCount(0);
  await segments(page).getByRole("radio", { name: /^Failing/ }).click();
  await expect(hosts(page).getByRole("checkbox")).toHaveCount(5);
  await hosts(page).first().getByRole("button", { name: "View evidence" }).click();
  await expect(card(page, /^Hosts/).getByText("Why it triggered")).toBeVisible();
  await expect(card(page, /^Hosts/).locator(".detection-verdict")).toContainText("Matched 1 of 1 condition");
});

test("tick a failing host and set its state; Reopen opens it again", async ({ page }) => {
  await page.goto(`${PAGE}?segment=failing`);
  await expect(hosts(page)).toHaveCount(5);
  const first = hosts(page).filter({ hasText: "Open" }).first();
  const name = (await first.locator("a").first().innerText()).trim();
  await first.getByRole("checkbox").check();
  const bar = page.getByRole("region", { name: "Bulk actions" });
  await expect(bar).toContainText("1 selected");
  await bar.getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^Mitigate/ }).click();
  const dialog = page.getByRole("dialog", { name: "Mitigate" });
  await dialog.getByRole("textbox").fill("PermitRootLogin no");
  await dialog.getByRole("button", { name: "Mitigate 1 host" }).click();
  await expect(page.locator(".toast").last()).toContainText("1 changed");
  const row = hosts(page).filter({ hasText: name });
  await expect(row).toContainText("Mitigated");
  await row.getByRole("checkbox").check();
  await bar.getByRole("button", { name: "Reopen 1 closed" }).click();
  await expect(page.locator(".toast").last()).toContainText("1 changed");
  await expect(row).toContainText("Open");
});

test("the header's Set state confirms the open failing host count", async ({ page }) => {
  await page.goto(PAGE);
  await page.locator(".person-page__actions").getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^Mitigate/ }).click();
  const dialog = page.getByRole("dialog", { name: "Mitigate" });
  await expect(dialog).toContainText("Changes up to 2 open failing hosts");
  await dialog.getByRole("textbox").fill("rolled out the hardened sshd_config");
  await dialog.getByRole("button", { name: /^Mitigate/ }).click();
  await expect(page.locator(".toast").last()).toContainText("2 changed");
  // Nothing is open any more: Set state and Assign go from the header.
  await expect(page.locator(".person-page__actions").getByRole("button", { name: /^Set state/ })).toHaveCount(0);
});

for (const scheme of ["light", "dark"] as const) {
  test(`the page passes axe (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto(PAGE);
    await expect(hosts(page).first()).toBeVisible();
    await hosts(page).filter({ hasText: "Open" }).first().getByRole("button", { name: "View evidence" }).click();
    await expect(card(page, /^Hosts/).getByText("Why it triggered")).toBeVisible();
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  });
}
