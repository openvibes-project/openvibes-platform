import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["coverage/**", "dist/**", "dist-demo/**", "dist-e2e/**", "test-results/**", "playwright-report/**", "node_modules/**"] },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ["public/**/*.js"],
    languageOptions: {
      globals: { document: "readonly", window: "readonly" },
    },
  },
  {
    files: ["src/**/*.{ts,tsx}", "e2e/**/*.ts", "vite.config.ts"],
    plugins: { "react-hooks": reactHooks },
    rules: reactHooks.configs.flat.recommended.rules,
  },
);
