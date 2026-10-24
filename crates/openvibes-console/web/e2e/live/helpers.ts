// Shared by the live specs: sign-in, a JSON call as the signed-in person,
// and a new person's first sign-in.
import { type Browser, type Page, expect } from "@playwright/test";

export const PASSWORD = "e2e-console-Passw0rd!";

export async function signIn(page: Page, username: string) {
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.locator(".view")).toBeVisible();
  await page.mouse.move(900, 600);
}

/** A JSON call from the page, as its signed-in person (session cookie, CSRF token, Origin). */
export async function api(page: Page, method: string, path: string, body?: unknown) {
  return page.evaluate(async ({ method, path, body }) => {
    const session = await (await fetch("/api/v1/session")).json() as { csrf_token: string };
    const response = await fetch(path, {
      method,
      headers: { "x-csrf-token": session.csrf_token, ...(body === undefined ? {} : { "content-type": "application/json" }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const text = await response.text();
    return { status: response.status, json: (text ? JSON.parse(text) : undefined) as unknown };
  }, { method, path, body });
}

/** A new person's first sign-in: the one-time password, then their own. */
export async function firstSignIn(browser: Browser, username: string, oneTime: string) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(oneTime);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByLabel("One-time password").fill(oneTime);
  await page.getByLabel("New password (at least 15 characters)").fill(PASSWORD);
  await page.getByLabel("New password again").fill(PASSWORD);
  await page.getByRole("button", { name: "Set password" }).click();
  await expect(page.locator(".view")).toBeVisible();
  return page;
}

/** The Compliance list's first check, on its page (approved screen 28, roles 5c),
 * leaving out compliance.spec.ts's per-browser sets (e2e-comp-P), which it triages. */
export async function openFirstCheck(page: Page) {
  await page.goto("/compliance");
  await page.locator('.view tbody tr a[href^="/compliance/"]:not([href^="/compliance/e2e-comp-"])').first().click();
  await page.getByRole("table", { name: "Hosts", exact: true }).waitFor();
}
