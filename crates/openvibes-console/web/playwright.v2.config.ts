import { defineConfig, devices } from "@playwright/test";

// Console v2 smoke tests against the demo build (no server needed).
const origin = "http://127.0.0.1:5175";

export default defineConfig({
  testDir: "./v2/e2e",
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: { baseURL: origin, screenshot: "only-on-failure", trace: "retain-on-failure" },
  webServer: {
    command: "VITE_V2_SOURCE=demo npx vite build --config vite.v2.config.ts --outDir ../dist-v2-e2e && npx vite preview --config vite.v2.config.ts --outDir ../dist-v2-e2e --port 5175 --strictPort",
    url: origin,
    reuseExistingServer: false,
    timeout: 120_000,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
    { name: "firefox", use: { ...devices["Desktop Firefox"], viewport: { width: 1440, height: 900 } } },
  ],
});
