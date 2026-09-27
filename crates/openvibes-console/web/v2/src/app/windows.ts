// Floating windows: panels popped out of the inspector, to compare two hosts
// or keep an advisory open while browsing. Positions are kept per viewer.
import { useSyncExternalStore } from "react";

import { type PanelRef, samePanel } from "./location";
import { nav } from "./nav";

export type Win = PanelRef & { x: number; y: number; w: number; h: number; z: number; min: boolean };

const key = "openvibes.v2.windows";
const listeners = new Set<() => void>();
let windows: Win[] = read();
let top = Math.max(10, ...windows.map((w) => w.z));

function read(): Win[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(key) ?? "[]") as unknown;
    return Array.isArray(parsed) ? parsed.filter((w): w is Win => typeof w?.kind === "string" && typeof w?.id === "string" && typeof w?.x === "number").slice(0, 12) : [];
  } catch {
    return [];
  }
}

function set(next: Win[]) {
  windows = next;
  try { localStorage.setItem(key, JSON.stringify(windows)); } catch { /* convenience only */ }
  for (const listener of listeners) listener();
}

/** Keeps a window reachable: its title bar stays inside the viewport. */
export function clamp(win: Win, width: number, height: number): Win {
  const w = Math.min(Math.max(320, win.w), Math.max(320, width - 16));
  const h = Math.min(Math.max(220, win.h), Math.max(220, height - 16));
  return { ...win, w, h, x: Math.min(Math.max(8 - w + 120, win.x), width - 120), y: Math.min(Math.max(8, win.y), height - 48) };
}

export const windowsStore = {
  popOut(ref: PanelRef) {
    nav.remove(ref);
    const existing = windows.find((w) => samePanel(w, ref));
    if (existing) { windowsStore.focus(existing); return; }
    const offset = (windows.length % 6) * 28;
    const w = Math.min(560, window.innerWidth - 32);
    const h = Math.min(640, window.innerHeight - 96);
    set([...windows, clamp({ ...ref, x: window.innerWidth - w - 420 + offset, y: 80 + offset, w, h, z: ++top, min: false }, window.innerWidth, window.innerHeight)]);
  },
  focus(ref: PanelRef) {
    set(windows.map((w) => samePanel(w, ref) ? { ...w, z: ++top, min: false } : w));
  },
  move(ref: PanelRef, x: number, y: number) {
    set(windows.map((w) => samePanel(w, ref) ? clamp({ ...w, x, y }, window.innerWidth, window.innerHeight) : w));
  },
  resize(ref: PanelRef, w: number, h: number) {
    set(windows.map((win) => samePanel(win, ref) ? clamp({ ...win, w, h }, window.innerWidth, window.innerHeight) : win));
  },
  minimize(ref: PanelRef) { set(windows.map((w) => samePanel(w, ref) ? { ...w, min: true } : w)); },
  close(ref: PanelRef) { set(windows.filter((w) => !samePanel(w, ref))); },
  dock(ref: PanelRef) {
    set(windows.filter((w) => !samePanel(w, ref)));
    nav.open(ref);
  },
  closeAll() { set([]); },
};

export function useWindows(): Win[] {
  return useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, () => windows);
}
