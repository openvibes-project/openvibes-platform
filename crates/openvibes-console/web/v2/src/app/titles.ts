// Readable names panels learn once their data loads (a host name for an
// agent id), used by breadcrumbs, window bars and the palette's recents.
import { useEffect, useSyncExternalStore } from "react";

import type { PanelRef } from "./location";

const titles = new Map<string, string>();
const listeners = new Set<() => void>();
let version = 0;
const keyOf = (ref: PanelRef) => `${ref.kind}:${ref.id}`;

export function panelTitle(ref: PanelRef): string | undefined {
  return titles.get(keyOf(ref));
}

/** Called by a panel with the name it loaded. */
export function useProvideTitle(ref: PanelRef, title: string | undefined): void {
  const key = keyOf(ref);
  useEffect(() => {
    if (!title || titles.get(key) === title) return;
    titles.set(key, title);
    version += 1;
    for (const listener of listeners) listener();
  }, [key, title]);
}

/** Re-renders the caller when any learned title changes. */
export function useTitles(): number {
  return useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, () => version);
}
