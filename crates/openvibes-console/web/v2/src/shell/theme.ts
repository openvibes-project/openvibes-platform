// Same storage key and semantics as v1 (and public/theme-bootstrap.js), so a
// viewer's choice carries over between the two consoles.
import { useSyncExternalStore } from "react";

export type Theme = "system" | "light" | "dark";
const key = "openvibes.theme";
const listeners = new Set<() => void>();

export function currentTheme(): Theme {
  const value = document.documentElement.dataset.themePreference;
  return value === "light" || value === "dark" ? value : "system";
}

export function setTheme(theme: Theme): void {
  const root = document.documentElement;
  root.dataset.themePreference = theme;
  if (theme === "system") root.removeAttribute("data-theme");
  else root.dataset.theme = theme;
  const dark = theme === "dark" || (theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", dark ? "#0e1419" : "#f4f5f7");
  try { localStorage.setItem(key, theme); } catch { /* the choice lasts until reload */ }
  for (const listener of listeners) listener();
}

export function useTheme(): Theme {
  return useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, currentTheme);
}

const densityKey = "openvibes.v2.density";
export type Density = "comfortable" | "compact";

export function applyStoredDensity(): void {
  try {
    if (localStorage.getItem(densityKey) === "compact") document.documentElement.dataset.density = "compact";
  } catch { /* default density */ }
}

export function currentDensity(): Density {
  return document.documentElement.dataset.density === "compact" ? "compact" : "comfortable";
}

export function setDensity(density: Density): void {
  if (density === "compact") document.documentElement.dataset.density = "compact";
  else delete document.documentElement.dataset.density;
  try { localStorage.setItem(densityKey, density); } catch { /* lasts until reload */ }
  for (const listener of listeners) listener();
}

export function useDensity(): Density {
  return useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, currentDensity);
}
