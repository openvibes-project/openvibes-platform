import { describe, expect, it } from "vitest";

import {
  applyThemePreference,
  parseThemePreference,
  readThemePreference,
  storeThemePreference,
  themeStorageKey,
} from "./theme";

describe("theme preferences", () => {
  it("allow-lists persisted values and falls back to system", () => {
    expect(parseThemePreference("light")).toBe("light");
    expect(parseThemePreference("dark")).toBe("dark");
    expect(parseThemePreference("sepia")).toBe("system");
    expect(parseThemePreference(null)).toBe("system");
  });

  it("falls back when storage cannot be read", () => {
    expect(
      readThemePreference({
        getItem: () => {
          throw new Error("blocked");
        },
      }),
    ).toBe("system");
  });

  it("stores a selected preference without coupling it to session state", () => {
    const entries = new Map<string, string>();
    storeThemePreference({ setItem: (key, value) => entries.set(key, value) }, "dark");
    expect(entries.get(themeStorageKey)).toBe("dark");
  });

  it("uses media-query styling for the system preference", () => {
    const dataset: DOMStringMap = {};
    const removed: string[] = [];

    applyThemePreference(
      {
        dataset,
        removeAttribute: (name) => {
          removed.push(name);
          delete dataset.theme;
        },
      },
      "system",
    );

    expect(dataset.themePreference).toBe("system");
    expect(removed).toEqual(["data-theme"]);
  });
});
