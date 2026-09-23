import { type ChangeEvent, useEffect, useState } from "react";

import {
  applyThemePreference,
  parseThemePreference,
  readThemePreference,
  storeThemePreference,
  themeStorageKey,
  type ThemePreference,
} from "../theme/theme";

function initialPreference(): ThemePreference {
  if (typeof window === "undefined") {
    return "system";
  }

  try {
    return readThemePreference(window.localStorage);
  } catch {
    return "system";
  }
}

function updateThemeColor(preference: ThemePreference): void {
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const dark = preference === "dark" || (preference === "system" && prefersDark);
  document
    .querySelector<HTMLMetaElement>('meta[name="theme-color"]')
    ?.setAttribute("content", dark ? "#11171d" : "#f5f4f0");
}

export function ThemeControl() {
  const [preference, setPreference] = useState<ThemePreference>(initialPreference);

  useEffect(() => {
    const colorScheme = window.matchMedia("(prefers-color-scheme: dark)");
    const handleStorage = (event: StorageEvent) => {
      if (event.key !== themeStorageKey) {
        return;
      }

      const nextPreference = parseThemePreference(event.newValue);
      setPreference(nextPreference);
      applyThemePreference(document.documentElement, nextPreference);
      updateThemeColor(nextPreference);
    };

    const handleColorScheme = () => updateThemeColor(preference);

    window.addEventListener("storage", handleStorage);
    colorScheme.addEventListener("change", handleColorScheme);
    return () => {
      window.removeEventListener("storage", handleStorage);
      colorScheme.removeEventListener("change", handleColorScheme);
    };
  }, [preference]);

  const handleChange = (event: ChangeEvent<HTMLSelectElement>) => {
    const nextPreference = parseThemePreference(event.currentTarget.value);
    setPreference(nextPreference);

    try {
      storeThemePreference(window.localStorage, nextPreference);
    } catch {
      // Accessing localStorage itself may be blocked by browser privacy policy.
    }

    applyThemePreference(document.documentElement, nextPreference);
    updateThemeColor(nextPreference);
  };

  return (
    <label className="theme-control">
      <span className="theme-control__label">Theme</span>
      <select value={preference} onChange={handleChange} aria-describedby="theme-selection-status">
        <option value="system">System</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
      <span id="theme-selection-status" className="sr-only" aria-live="polite">
        Theme preference: {preference}
      </span>
    </label>
  );
}
