import { defineConfig, devices } from "@playwright/test";

const consoleOrigin = "http://127.0.0.1:18490";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  ...(process.env.CI ? { workers: 1 } : {}),
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: consoleOrigin,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: {
    command:
      "../../../target/debug/examples/seeded_server --config ../tests/fixtures/e2e.toml",
    url: consoleOrigin,
    reuseExistingServer: false,
    timeout: 30_000,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
