import { defineConfig } from "vitest/config";

export default defineConfig({
  build: {
    assetsInlineLimit: 0,
    manifest: true,
    outDir: "dist",
    emptyOutDir: true,
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
