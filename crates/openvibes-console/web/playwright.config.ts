import { defineConfig, devices } from "@playwright/test";

// The real console (embedded UI, CSP and all) on a throwaway database;
// scripts/test-console-e2e.sh builds it and scripts/console-e2e-server.sh
// prepares the data and starts it.
const origin = "http://127.0.0.1:18490";

export default defineConfig({
  testDir: "./e2e/live",
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: { baseURL: origin, screenshot: "only-on-failure", trace: "retain-on-failure" },
  webServer: {
    command: "bash ../../../scripts/console-e2e-server.sh",
    url: `${origin}/login`,
    reuseExistingServer: false,
    timeout: 120_000,
    // The console logs every request; failures carry traces and screenshots instead.
    stdout: "ignore",
    stderr: "ignore",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
    { name: "firefox", use: { ...devices["Desktop Firefox"], viewport: { width: 1440, height: 900 } } },
    { name: "webkit", use: { ...devices["Desktop Safari"], viewport: { width: 1440, height: 900 } } },
  ],
});
