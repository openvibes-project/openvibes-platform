export const themeStorageKey = "openvibes.theme";

export type ThemePreference = "system" | "light" | "dark";

type StorageReader = Pick<Storage, "getItem">;
type StorageWriter = Pick<Storage, "setItem">;
type ThemeRoot = Pick<HTMLElement, "dataset" | "removeAttribute">;

export function parseThemePreference(value: string | null): ThemePreference {
  if (value === "light" || value === "dark") {
    return value;
  }

  return "system";
}

export function readThemePreference(storage: StorageReader): ThemePreference {
  try {
    return parseThemePreference(storage.getItem(themeStorageKey));
  } catch {
    return "system";
  }
}

export function storeThemePreference(storage: StorageWriter, preference: ThemePreference): void {
  try {
    storage.setItem(themeStorageKey, preference);
  } catch {
    // A blocked storage API must not prevent the theme control from working.
  }
}

export function applyThemePreference(root: ThemeRoot, preference: ThemePreference): void {
  root.dataset.themePreference = preference;

  if (preference === "system") {
    root.removeAttribute("data-theme");
    return;
  }

  root.dataset.theme = preference;
}
