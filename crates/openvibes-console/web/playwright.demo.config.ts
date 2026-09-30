import { defineConfig, devices } from "@playwright/test";

// The in-browser demo build (the GitHub Pages preview), no server needed.
const origin = "http://127.0.0.1:5175";

export default defineConfig({
  testDir: "./e2e/demo",
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: { baseURL: origin, screenshot: "only-on-failure", trace: "retain-on-failure" },
  webServer: {
    command: "VITE_DEMO=true node_modules/.bin/vite build --outDir dist-e2e && node_modules/.bin/vite preview --outDir dist-e2e --port 5175 --strictPort",
    url: origin,
    reuseExistingServer: false,
    timeout: 120_000,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
    { name: "firefox", use: { ...devices["Desktop Firefox"], viewport: { width: 1440, height: 900 } } },
  ],
});
