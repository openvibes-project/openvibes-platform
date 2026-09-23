import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

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
  const cspMessages: string[] = [];
  page.on("console", (message) => {
    if (message.text().toLowerCase().includes("content security policy")) {
      cspMessages.push(message.text());
    }
  });

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

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(accessibility.violations).toEqual([]);
  expect(cspMessages).toEqual([]);
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
});
