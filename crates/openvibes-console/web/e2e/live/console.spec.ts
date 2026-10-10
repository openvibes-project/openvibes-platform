// The shipped console against a real server: production CSP, no third-party
// requests, sign-in, every view, triage, dashboards shared between two people,
// and accessibility in both themes.
import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

const PASSWORD = "e2e-console-Passw0rd!";
const origin = "https://127.0.0.1:18490";

declare global {
  interface Window { cspViolations?: string[] }
}

async function watch(page: Page) {
  const thirdParty: string[] = [];
  page.on("request", (request) => { if (!request.url().startsWith(origin) && !request.url().startsWith("data:")) thirdParty.push(request.url()); });
  await page.addInitScript(() => {
    window.cspViolations = [];
    document.addEventListener("securitypolicyviolation", (event) => window.cspViolations?.push(`${event.violatedDirective} ${event.blockedURI}`));
  });
  return {
    csp: () => page.evaluate(() => window.cspViolations ?? []),
    thirdParty,
  };
}

async function signIn(page: Page, username: string) {
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".view")).toBeVisible();
  await page.mouse.move(900, 600);
}

test("sign-in, every view, and no CSP violations or third-party requests", async ({ page }) => {
  const checks = await watch(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByText("Explore the demo")).toHaveCount(0);
  await expect(page.getByText("Demo data")).toHaveCount(0);
  await signIn(page, "alex");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("Alex");
  for (const view of ["/compliance", "/vulnerabilities", "/agents", "/enrollment", "/rule-sets", "/access", "/service-accounts", "/audit"]) {
    await page.goto(view);
    await expect(page.locator(".view")).toBeVisible();
    await expect(page.locator(".error-box")).toHaveCount(0);
  }
  expect(await checks.csp()).toEqual([]);
  expect(checks.thirdParty).toEqual([]);
});

// #260: the sign-in token is single-use and lives 5 minutes; the page took
// it once, so a typo or a page left open (after an inactivity sign-out)
// failed every later attempt as "incorrect" until a reload.
test("a mistyped password, then the right one, signs in without a reload", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Username").fill("alex");
  await page.getByLabel("Password").fill("not-the-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("incorrect");
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".view")).toBeVisible();
});

test("a sign-in page left open past its token's lifetime still signs in", async ({ page, context }) => {
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Sign in" })).toBeEnabled();
  // The token's cookies expire after 5 minutes: as if the page sat that long.
  await context.clearCookies();
  await page.getByLabel("Username").fill("alex");
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".view")).toBeVisible();
});

test("/login shows home once signed in, and /assistant is gone", async ({ page }) => {
  await signIn(page, "alex");
  await page.goto("/login");
  await expect(page).toHaveURL(`${origin}/`);
  const response = await page.request.get("/assistant");
  expect(response.status()).toBe(404);
});

test("an empty service accounts view explains the next step", async ({ page }) => {
  await signIn(page, "alex");
  await page.goto("/service-accounts");
  await expect(page.getByText("No service accounts")).toBeVisible();
  await expect(page.getByText("Create one for integrations that need API access.")).toBeVisible();
});

test("with no alarm at all, the Alarms view says how to turn alarms on", async ({ page }) => {
  await signIn(page, "alex");
  await page.goto("/alarms");
  await expect(page.getByText("No alarms")).toBeVisible();
  await expect(page.getByText(/"process_events" is in their collectors/)).toBeVisible();
});

test("Most exposed hosts ranks hosts across all kinds even before any feed imported", async ({ page }) => {
  // No vulnerability feed here, but compliance findings exist: the Overview's
  // all-kinds ranking lists those hosts and claims no vulnerability scan (board #47).
  await signIn(page, "alex");
  const tile = page.locator(".tile", { hasText: "Most exposed hosts" });
  const row = tile.locator(".list__row").first();
  await expect(row).toContainText(/\d+ open$/);
  await expect(row).toHaveAttribute("href", /agent/);
  await expect(tile.getByText("No host has an open")).toHaveCount(0);
});

test("the Overview's Active alarms tile draws a line from its first value, and the Critical tile adds up and links", async ({ page }) => {
  await signIn(page, "alex");
  const tileOf = (title: RegExp) => page.locator(".tile", { has: page.locator(".tile__title", { hasText: title }) });
  // One history point so far (today's live value): a flat line, not an empty tile (#238).
  // (A flat path has a zero-height box, so count it rather than ask if it is visible.)
  await expect(tileOf(/^Active alarms$/).locator("svg .linechart__line")).toHaveCount(1);
  await expect(tileOf(/^Active alarms$/).getByText(/^(No data yet|Collecting since)/)).toHaveCount(0);
  const tile = tileOf(/^Critical$/);
  // Every number loaded before they are added up.
  await expect(tile.locator(".stat__value")).toHaveText(/^\d[\d,]*$/);
  await expect(tile.locator(".tile-parts")).not.toContainText("…");
  const total = Number((await tile.locator(".stat__value").textContent())?.replace(/\D/g, ""));
  const parts = (await tile.locator(".tile-parts").textContent()) ?? "";
  const sum = [...parts.matchAll(/(\d[\d,]*) (?:alarm|vulnerabilit|compliance)/g)].reduce((n, m) => n + Number((m[1] ?? "").replace(/,/g, "")), 0);
  expect(sum).toBe(total);
  await tile.getByRole("button", { name: /alarm/ }).click();
  await expect(page).toHaveURL(/severity=critical/);
});

test("vulnerability number tiles show no zero before any feed imported", async ({ page }) => {
  // A 0 would claim nothing was found; nothing was looked for (board #47).
  await signIn(page, "alex");
  for (const title of ["Exploited", "need a reboot"]) {
    const tile = page.locator(".tile", { hasText: title });
    await expect(tile.locator(".stat__value")).toHaveText("—");
    // Read aloud as "Not set up", not "dash, Not set up".
    await expect(tile.getByRole("button")).toHaveAccessibleName("Not set up");
    const note = tile.getByText("Not set up");
    await expect(note).toBeVisible();
    // Inside the tile, not cut off by its fixed height.
    const bottom = async (l: typeof tile) => { const b = await l.boundingBox(); if (!b) throw new Error("not rendered"); return b.y + b.height; };
    expect(await bottom(note)).toBeLessThanOrEqual(await bottom(tile));
  }
});

test("an Access filter with no matches explains the empty list", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ colorScheme: "light" });
  await signIn(page, "alex");
  await page.goto("/access?q=no-such-person");
  await expect(page.getByText("Nothing matches these filters")).toBeVisible();
  await expect(page.getByText("Clear a filter to see more.")).toBeVisible();
});

test("an Audit filter with no matches explains the empty list", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.emulateMedia({ colorScheme: "dark" });
  await signIn(page, "alex");
  await page.goto("/audit?q=no-such-action");
  await expect(page.getByText("Nothing matches these filters")).toBeVisible();
  await expect(page.getByText("Clear a filter to see more.")).toBeVisible();
});

test("an old /findings link lands on /compliance with its filters", async ({ page }) => {
  await signIn(page, "alex");
  await page.goto("/findings?severity=high");
  await expect(page).toHaveURL(/\/compliance\?severity=high$/);
  await expect(page.locator(".view")).toBeVisible();
});

test("open hosts of a finding are mitigated in bulk from the Hosts tab, with a note", async ({ page }, info) => {
  await signIn(page, "alex");
  await page.goto("/compliance");
  const row = page.locator(".view tbody tr").first();
  await row.locator("td").nth(2).click();
  await expect(page.locator(".panel-header__kind")).toContainText("Compliance finding");
  const inspector = page.locator(".inspector");
  await inspector.getByRole("group", { name: "Show hosts by triage state" }).getByRole("button", { name: /^Open \d/ }).click();
  await inspector.getByRole("checkbox", { name: "Select the rows on screen" }).check();
  await inspector.getByRole("region", { name: "Bulk actions" }).getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^Mitigate/ }).click();
  const dialog = page.getByRole("dialog", { name: "Mitigate" });
  const confirm = dialog.getByRole("button", { name: /^Mitigate \d+ hosts?$/ });
  await confirm.click();
  await expect(dialog.getByRole("alert")).toContainText("note");
  await dialog.getByRole("textbox", { name: "Why (required)" }).fill(`e2e ${info.project.name}`);
  await confirm.click();
  await expect(page.locator(".toast")).toContainText("changed");
  await inspector.getByRole("tab", { name: /^History/ }).click();
  await expect(inspector.locator(".detail-history")).toContainText(`e2e ${info.project.name}`);
});

test("one host's risk is accepted until a date, then assigned", async ({ page }) => {
  await signIn(page, "alex");
  await page.goto("/compliance");
  await page.locator(".view tbody tr").first().locator("td").nth(2).click();
  await expect(page.locator(".panel-header__kind")).toContainText("Compliance finding");
  const inspector = page.locator(".inspector");
  const host = inspector.locator("tbody tr").first();
  const name = (await host.locator("a").first().innerText()).trim();
  await host.getByRole("checkbox", { name: "Select row" }).check();
  const bar = inspector.getByRole("region", { name: "Bulk actions" });
  await bar.getByRole("button", { name: /^Set state/ }).click();
  await page.getByRole("menuitem", { name: /^Accept risk/ }).click();
  const until = new Date(Date.now() + 30 * 86_400_000).toISOString().slice(0, 10);
  const dialog = page.getByRole("dialog", { name: "Accept risk" });
  await dialog.getByLabel("Accepted until").fill(until);
  await dialog.getByRole("textbox", { name: "Why (required)" }).fill("vendor fix due");
  await dialog.getByRole("button", { name: "Accept risk for 1 host" }).click();
  await expect(page.locator(".toast").last()).toContainText("1 changed");
  const row = inspector.locator("tbody tr").filter({ hasText: name });
  await expect(row).toContainText("Accepted risk");
  await row.getByRole("checkbox", { name: "Select row" }).check();
  // Picking a person applies at once (#253): no dialog.
  await bar.getByRole("combobox", { name: /^Assign/ }).click();
  await page.getByRole("combobox", { name: /^Filter Assign/ }).fill("sam");
  await page.getByRole("option", { name: /sam/i }).first().click();
  await expect(page.locator(".toast").last()).toContainText("1 changed");
  await expect(inspector.locator("tbody tr").filter({ hasText: name })).toContainText(/sam/i);
});

test("a dashboard is created, saved, shared and seen read-only by an analyst", async ({ page, browser }, info) => {
  const name = `Team board ${info.project.name}`;
  const checks = await watch(page);
  await signIn(page, "alex");
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await page.getByRole("button", { name: /^Number/ }).click();
  await page.getByRole("combobox", { name: "Count", exact: true }).click();
  await page.getByRole("option", { name: "Open critical compliance findings", exact: true }).click();
  await page.getByLabel("Dashboard name").fill(name);
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(name);
  await page.getByRole("button", { name: "Dashboard menu" }).click();
  await page.getByRole("menuitemradio", { name: "analyst" }).click();
  await expect(page.locator("#main").getByText("Shared with analyst")).toBeVisible();
  const url = page.url();
  await page.reload();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(name);
  expect(await checks.csp()).toEqual([]);

  const sam = await browser.newPage();
  await signIn(sam, "sam");
  await sam.goto(url);
  await expect(sam.getByRole("heading", { level: 1 })).toHaveText(name);
  await expect(sam.getByText("Shared by Alex Admin")).toBeVisible();
  await expect(sam.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  await sam.close();
});

for (const scheme of ["light", "dark"] as const) {
  test(`no accessibility violations when signed in (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await signIn(page, "alex");
    for (const path of ["/", "/compliance", "/audit"]) {
      await page.goto(path);
      await expect(page.locator(".view")).toBeVisible();
      await page.waitForTimeout(500);
      const result = await new AxeBuilder({ page }).analyze();
      expect(result.violations.flatMap((v) => v.nodes.map((n) => `${path} ${v.id}: ${n.target.join(" ")}`))).toEqual([]);
    }
  });
}

test("a new user signs in with a one-time password and must set their own first (board #85)", async ({ page, browser }, info) => {
  await signIn(page, "alex");
  await page.goto("/access");
  await page.getByRole("button", { name: "New user" }).click();
  const username = `e2e-${info.project.name}-${Date.now().toString(36)}`;
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Display name").fill("E2E Person");
  await page.getByRole("combobox", { name: "Role" }).click();
  await page.getByRole("option", { name: /viewer/i }).click();
  await page.getByRole("button", { name: "Create user" }).click();
  const oneTime = (await page.locator(".secret .grow").innerText()).trim();
  expect(oneTime.length).toBeGreaterThanOrEqual(15);

  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const other = await context.newPage();
  await other.goto("/");
  await other.getByLabel("Username").fill(username);
  await other.getByLabel("Password").fill(oneTime);
  await other.getByRole("button", { name: "Sign in" }).click();
  await expect(other.getByRole("heading", { name: "Set your password" })).toBeVisible();
  await expect(other.locator(".rail")).toHaveCount(0);
  // A second tab of the same session (tripwire #1604).
  const secondTab = await context.newPage();
  await secondTab.goto("/");
  await expect(secondTab.getByRole("heading", { name: "Set your password" })).toBeVisible();
  await other.getByLabel("One-time password").fill(oneTime);
  await other.getByLabel("New password (at least 15 characters)").fill("e2e-a-long-new-password-2026");
  await other.getByLabel("New password again").fill("e2e-a-long-new-password-2026");
  await other.getByRole("button", { name: "Set password" }).click();
  await expect(other.locator(".view")).toBeVisible();
  // The stale tab, used with the spent one-time password, goes to the console.
  await secondTab.getByLabel("One-time password").fill(oneTime);
  await secondTab.getByLabel("New password (at least 15 characters)").fill("e2e-another-long-password-2026");
  await secondTab.getByLabel("New password again").fill("e2e-another-long-password-2026");
  await secondTab.getByRole("button", { name: "Set password" }).click();
  await expect(secondTab.locator(".view")).toBeVisible();
  await context.close();
});
