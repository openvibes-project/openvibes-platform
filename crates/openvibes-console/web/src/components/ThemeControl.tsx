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

export function ThemeControl() {
  const [preference, setPreference] = useState<ThemePreference>(initialPreference);

  useEffect(() => {
    const handleStorage = (event: StorageEvent) => {
      if (event.key !== themeStorageKey) {
        return;
      }

      const nextPreference = parseThemePreference(event.newValue);
      setPreference(nextPreference);
      applyThemePreference(document.documentElement, nextPreference);
    };

    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, []);

  const handleChange = (event: ChangeEvent<HTMLSelectElement>) => {
    const nextPreference = parseThemePreference(event.currentTarget.value);
    setPreference(nextPreference);

    try {
      storeThemePreference(window.localStorage, nextPreference);
    } catch {
      // Accessing localStorage itself may be blocked by browser privacy policy.
    }

    applyThemePreference(document.documentElement, nextPreference);
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
