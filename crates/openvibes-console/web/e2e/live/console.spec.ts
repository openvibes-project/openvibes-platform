// The shipped console against a real server: production CSP, no third-party
// requests, sign-in, every view, triage, dashboards shared between two people,
// and accessibility in both themes.
import AxeBuilder from "@axe-core/playwright";
import { type Page, expect, test } from "@playwright/test";

const PASSWORD = "e2e-console-Passw0rd!";
const origin = "http://127.0.0.1:18490";

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
  await expect(page.getByRole("link", { name: "Findings" })).toBeVisible();
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
  for (const view of ["/findings", "/vulnerabilities", "/agents", "/enrollment", "/rule-sets", "/access", "/service-accounts", "/audit"]) {
    await page.goto(view);
    await expect(page.locator(".view")).toBeVisible();
    await expect(page.locator(".error-box")).toHaveCount(0);
  }
  expect(await checks.csp()).toEqual([]);
  expect(checks.thirdParty).toEqual([]);
});

test("/login shows home once signed in, and /assistant is gone", async ({ page }) => {
  await signIn(page, "alex");
  await page.goto("/login");
  await expect(page).toHaveURL(`${origin}/`);
  const response = await page.request.get("/assistant");
  expect(response.status()).toBe(404);
});

test("imported findings are triaged in bulk from the panel", async ({ page }, info) => {
  await signIn(page, "alex");
  await page.goto("/findings");
  await page.locator(".view tbody tr").first().locator("td").nth(1).click();
  await expect(page.locator(".panel-header__kind")).toContainText("Finding");
  await page.getByRole("checkbox", { name: "Select all hosts" }).check();
  await page.getByLabel("New triage state").selectOption("investigating");
  await page.getByLabel("Triage note").fill(`e2e ${info.project.name}`);
  await page.locator(".bulk-bar button[type=submit]").click();
  await expect(page.locator(".toast")).toContainText("set to investigating");
});

test("a dashboard is created, saved, shared and seen read-only by an analyst", async ({ page, browser }, info) => {
  const name = `Team board ${info.project.name}`;
  const checks = await watch(page);
  await signIn(page, "alex");
  await page.getByRole("button", { name: "Dashboards" }).click();
  await page.getByRole("menuitem", { name: "New dashboard" }).click();
  await page.getByRole("button", { name: /^Number/ }).click();
  await page.getByLabel("Count", { exact: true }).selectOption("findings.open.critical");
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
    for (const path of ["/", "/findings", "/audit"]) {
      await page.goto(path);
      await expect(page.locator(".view")).toBeVisible();
      await page.waitForTimeout(500);
      const result = await new AxeBuilder({ page }).analyze();
      expect(result.violations.flatMap((v) => v.nodes.map((n) => `${path} ${v.id}: ${n.target.join(" ")}`))).toEqual([]);
    }
  });
}
