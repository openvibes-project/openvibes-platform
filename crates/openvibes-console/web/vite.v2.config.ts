import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

// Console v2 (experimental): its own root, sharing node_modules, the
// OpenAPI types and the brand assets with v1. V2_BASE sets the public
// path (GitHub Pages serves it under /<repository>/).
export default defineConfig({
  root: fileURLToPath(new URL("./v2", import.meta.url)),
  base: process.env.V2_BASE ?? "/",
  publicDir: fileURLToPath(new URL("./public", import.meta.url)),
  server: {
    host: "127.0.0.1",
    port: 5174,
    proxy: {
      "/api": { target: process.env.V2_LIVE ?? "http://127.0.0.1:18490" },
      "/auth": { target: process.env.V2_LIVE ?? "http://127.0.0.1:18490" },
    },
  },
  build: {
    outDir: fileURLToPath(new URL("./dist-v2", import.meta.url)),
    emptyOutDir: true,
    assetsInlineLimit: 0,
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
