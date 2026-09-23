import { applyThemePreference, readThemePreference, type ThemePreference } from "./theme";

let preference: ThemePreference = "system";

try {
  preference = readThemePreference(window.localStorage);
} catch {
  // System theme remains available when browser storage is unavailable.
}

applyThemePreference(document.documentElement, preference);
