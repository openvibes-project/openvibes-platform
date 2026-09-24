import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

declare global {
  interface Window {
    openvibesCspViolations?: string[];
  }
}

/**
 * Records every CSP violation, report-only included, from the page's own
 * `securitypolicyviolation` events. Console text differs between browsers
 * (Firefox writes "Content-Security-Policy"), so it is not scraped.
 */
async function recordCspViolations(page: Page): Promise<() => Promise<string[]>> {
  await page.addInitScript(() => {
    window.openvibesCspViolations = [];
    document.addEventListener("securitypolicyviolation", (event) => {
      window.openvibesCspViolations?.push(`${event.effectiveDirective} ${event.blockedURI}`);
    });
  });
  return () => page.evaluate(() => window.openvibesCspViolations ?? []);
}

const targetCsp = [
  "default-src 'none'",
  "script-src 'self'",
  "script-src-attr 'none'",
  "style-src 'self'",
  "style-src-attr 'none'",
  "img-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "manifest-src 'self'",
];

test("serves the accessible shell with the target security boundary", async ({ page }) => {
  const cspViolations = await recordCspViolations(page);

  const response = await page.goto("/");
  expect(response?.status()).toBe(200);
  const headers = response?.headers() ?? {};
  const csp = headers["content-security-policy-report-only"] ?? "";
  for (const directive of targetCsp) {
    expect(csp).toContain(directive);
  }
  expect(csp).not.toContain("'unsafe-inline'");
  expect(csp).not.toContain("'unsafe-eval'");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["referrer-policy"]).toBe("no-referrer");

  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Console" })).toBeVisible();
  await expect(page.getByLabel("Theme")).toHaveValue("system");
  const brandImages = page.getByRole("link", { name: "OpenVIBES Console home" }).locator("img");
  expect(await brandImages.count()).toBe(2);
  for (let index = 0; index < (await brandImages.count()); index += 1) {
    await expect(brandImages.nth(index)).toHaveJSProperty("complete", true);
    expect(
      await brandImages.nth(index).evaluate((image) => (image as HTMLImageElement).naturalWidth),
    ).toBeGreaterThan(0);
  }

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
  expect(await cspViolations()).toEqual([]);
});

test("applies and persists an explicit theme before application startup", async ({ page }) => {
  await page.addInitScript(() => {
    if (localStorage.getItem("openvibes.theme") === null) {
      localStorage.setItem("openvibes.theme", "dark");
    }
  });
  await page.goto("/findings", { waitUntil: "domcontentloaded" });

  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", "#11171d");
  await expect(page.getByLabel("Theme")).toHaveValue("dark");

  await page.getByLabel("Theme").selectOption("light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", "#f5f4f0");
});

test("keeps reserved route families out of SPA fallback", async ({ request }) => {
  const api = await request.get("/api/v1/not-a-route");
  expect(api.status()).toBe(404);
  expect(api.headers()["content-type"]).toContain("application/problem+json");
  expect((await api.json()).code).toBe("api_not_found");

  const auth = await request.get("/auth/not-a-route");
  expect(auth.status()).toBe(404);
  expect((await auth.json()).code).toBe("auth_not_found");

  const asset = await request.get("/assets/not-a-route.js");
  expect(asset.status()).toBe(404);
  expect(await asset.text()).toBe("");

  const health = await request.get("/health");
  expect(health.status()).toBe(404);
});

test("supports keyboard entry and the compact-navigation control", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content")).toBeFocused();

  const collapse = page.getByRole("button", { name: "Collapse primary navigation" });
  await collapse.click();
  await expect(page.getByRole("button", { name: "Expand primary navigation" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page.getByRole("link", { name: "OpenVIBES Console home" }).locator("img")).toHaveAttribute(
    "src",
    "/brand/openvibes-mark.svg",
  );
});

test("keeps native menu, dialog, and combobox primitives keyboard accessible", async ({ page }) => {
  const cspViolations = await recordCspViolations(page);

  await page.goto("/");
  await expect(page.getByRole("combobox", { name: "Theme" })).toBeVisible();

  const help = page.getByRole("button", { name: "Help" });
  await help.click();
  const menu = page.getByRole("menu", { name: "Help" });
  await expect(menu).toBeVisible();

  const about = page.getByRole("menuitem", { name: "About this console" });
  const findings = page.getByRole("menuitem", { name: "Open findings" });
  await expect(about).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(findings).toBeFocused();
  await page.keyboard.press("Home");
  await expect(about).toBeFocused();
  await about.click();

  const dialog = page.getByRole("dialog", { name: "About this console" });
  await expect(dialog).toBeVisible();
  await expect(page.getByRole("button", { name: "Close about this console dialog" })).toBeFocused();
  expect((await new AxeBuilder({ page }).include("dialog").analyze()).violations).toEqual([]);

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(help).toBeFocused();
  expect(await cspViolations()).toEqual([]);
});
