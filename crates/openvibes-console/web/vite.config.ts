import { defineConfig } from "vitest/config";

// The console's web interface. `npm run build` produces the embedded UI
// (web/dist, with the manifest the Rust build validates). CONSOLE_BASE sets
// the public path (GitHub Pages serves the demo under /<repository>/);
// CONSOLE_URL is where `npm run dev` proxies /api and /auth.
const target = process.env.CONSOLE_URL ?? "http://127.0.0.1:18490";

export default defineConfig({
  base: process.env.CONSOLE_BASE ?? "/",
  server: {
    host: "127.0.0.1",
    port: 5174,
    proxy: { "/api": { target }, "/auth": { target } },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    manifest: true,
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["src/test-setup.ts"],
  },
});
