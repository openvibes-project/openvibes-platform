import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

// A vulnerability's page (approved screen 26) on the demo: the demo answers
// GET /api/v1/vulnerabilities/{key}/summary and /hosts like
// vulnerabilities/page.rs. CVE-2026-20037 (demo/vulnSeed.ts) is covered by
// FEDORA-2026-5b1e0c11 (which also names CVE-2026-20051) and DSA-5891-1: four
// open hosts, one mitigated, one fixed, CISA's due date three days ago. The
// demo keeps its data in memory, so a test that changes triage never reloads.
const heading = (page: Page) => page.getByRole("heading", { level: 1 });
const card = (page: Page, title: string | RegExp) => page.locator(".person-card").filter({ has: page.getByRole("heading", { name: title }) });
const hosts = (page: Page) => card(page, /^Hosts/).locator("tbody tr");
const segments = (page: Page) => page.getByRole("radiogroup", { name: "Hosts by state" });

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await expect(heading(page)).toContainText("Alex");
  await page.mouse.move(900, 500);
});

test("old_advisory_links_open_the_page: one CVE, no CVE and several CVEs, with no dead history entry", async ({ page }) => {
  // An advisory naming one CVE: that CVE's page, the URL replaced.
  await page.goto("/vulnerabilities");
  await expect(page.getByRole("table", { name: "Vulnerabilities" })).toBeVisible();
  await page.goto("/?open=advisory%3AFEDORA-2026-3a1f9c0d");
  await expect(page).toHaveURL(/\/vulnerabilities\/CVE-2026-10000$/);
  await expect(heading(page)).toBeVisible();
  await expect(page.locator(".inspector")).toHaveCount(0);
  await page.goBack();
  await expect(page).toHaveURL(/\/vulnerabilities$/);
  // An advisory without a CVE: its own page.
  await page.goto("/vulnerabilities?open=advisory%3ADSA-5912-1");
  await expect(page).toHaveURL(/\/vulnerabilities\/DSA-5912-1$/);
  await expect(heading(page)).toHaveText("less security update");
  // An advisory naming several CVEs: the list filtered by it, every state.
  await page.goto("/?open=advisory%3AFEDORA-2026-3a2055a7");
  await expect(page).toHaveURL(/\/vulnerabilities\?advisory=FEDORA-2026-3a2055a7&state=all$/);
  const rows = page.getByRole("table", { name: "Vulnerabilities" }).locator("tbody tr");
  await expect(rows.filter({ hasText: "CVE-2026-10222" })).toHaveCount(1);
  await expect(rows.filter({ hasText: "CVE-2026-10227" })).toHaveCount(1);
  await page.goBack();
  await expect(page).toHaveURL(/\/vulnerabilities\/DSA-5912-1$/);
  // A link to an advisory elsewhere (the host page's Vulnerabilities) opens the page too.
  await page.goto("/hosts/agent-00001");
  const link = card(page, /^Vulnerabilities/).locator("tbody a").first();
  await expect(link).toHaveAttribute("href", /^\/vulnerabilities\/[^?]+$/);
  await link.click();
  await expect(page).toHaveURL(/\/vulnerabilities\/[^?]+$/);
  await expect(card(page, /^Hosts/)).toBeVisible();
});

test("switches the Hosts segments, and an unknown one reads as All", async ({ page }) => {
  await page.goto("/vulnerabilities/CVE-2026-20037");
  await expect(hosts(page)).not.toHaveCount(0);
  await segments(page).getByRole("radio", { name: /^Mitigated/ }).click();
  await expect(page).toHaveURL(/[?&]segment=mitigated/);
  await expect(hosts(page)).toHaveCount(1);
  await expect(hosts(page)).toContainText("Mitigated");
  await segments(page).getByRole("radio", { name: /^Open/ }).click();
  for (const text of await hosts(page).allTextContents()) expect(text).toContain("Open");
  await page.goto("/vulnerabilities/CVE-2026-20037?segment=bogus");
  await expect(segments(page).getByRole("radio", { name: /^All/ })).toHaveAttribute("aria-checked", "true");
  // A version-range match has no triage: no checkbox, and a note says why.
  await page.goto("/vulnerabilities/CVE-2026-20112");
  await expect(hosts(page).first()).toBeVisible();
  await expect(hosts(page).getByRole("checkbox")).toHaveCount(0);
});

test("tick two hosts and Set state: those pairs change, and Reopen opens one again", async ({ page }) => {
  await page.goto("/vulnerabilities/CVE-2026-20037?segment=open");
  await expect(hosts(page)).toHaveCount(4);
  await hosts(page).nth(0).getByRole("checkbox").check();
  await hosts(page).nth(1).getByRole("checkbox").check();
  const bar = page.getByRole("region", { name: "Bulk actions" });
  await expect(bar).toContainText("2 selected");
  await bar.getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^Mitigate/ }).click();
  const dialog = page.getByRole("dialog", { name: "Mitigate" });
  await dialog.getByRole("textbox").fill("blocked at the firewall");
  await dialog.getByRole("button", { name: "Mitigate 2 hosts" }).click();
  await expect(page.locator(".toast").last()).toContainText("2 changed");
  await expect(hosts(page)).toHaveCount(2);
  await segments(page).getByRole("radio", { name: /^Mitigated/ }).click();
  await expect(hosts(page)).toHaveCount(3);
  await hosts(page).first().getByRole("checkbox").check();
  await bar.getByRole("button", { name: "Reopen 1 closed" }).click();
  await expect(page.locator(".toast").last()).toContainText("1 changed");
  await expect(hosts(page)).toHaveCount(2);
});

test("the header's Set state confirms the open host count and names the other CVEs", async ({ page }) => {
  await page.goto("/vulnerabilities/CVE-2026-20037");
  await page.locator(".person-page__actions").getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^Mitigate/ }).click();
  const dialog = page.getByRole("dialog", { name: "Mitigate" });
  await expect(dialog).toContainText("Changes up to 4 open hosts");
  await expect(dialog).toContainText("Hosts without a fix yet are left as they are");
  await expect(dialog).toContainText("CVE-2026-20051");
  await dialog.getByRole("textbox").fill("patched upstream");
  await dialog.getByRole("button", { name: /^Mitigate/ }).click();
  await expect(page.locator(".toast").last()).toContainText("4 changed");
  await expect(page.locator(".detail-tiles").getByRole("link", { name: /^Open, of 6 hosts: 0$/ })).toBeVisible();
});

test("the due banner says when CISA wants it fixed", async ({ page }) => {
  await page.goto("/vulnerabilities/CVE-2026-20037");
  await expect(page.locator(".detail-page__banner")).toContainText(/Known exploited: CISA asks for remediation by .+ \(3 days ago\)\./);
  await expect(page.locator(".person-page__head").getByText("Known exploited")).toBeVisible();
  await expect(page.locator(".person-page__head").getByRole("link", { name: "CVE-2026-20037" })).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2026-20037");
  await page.goto("/vulnerabilities/CVE-2026-20042");
  await expect(page.locator(".detail-page__banner")).toContainText(/\(in 60 days\)\./);
  await page.goto("/vulnerabilities/CVE-2026-10000");
  await expect(card(page, /^Hosts/)).toBeVisible();
  await expect(page.locator(".detail-page__banner")).toHaveCount(0);
});

for (const scheme of ["light", "dark"] as const) {
  test(`the page passes axe (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto("/vulnerabilities/CVE-2026-20037");
    await expect(hosts(page).first()).toBeVisible();
    expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  });
}
