// Alarms show up without a reload: while the console is visible it asks
// for the newest active alarm every few seconds. When that changes, alarm
// views refresh, a new alarm gets a toast, and the menu's Alarms count is
// recounted. One small request per poll; no websocket. The Alarms list
// (a heavier query with counts) refreshes at most every 30 s.
import { useEffect, useSyncExternalStore } from "react";

import { invalidate, request, subscribe } from "../api/client";
import type { AlarmPage } from "../api/types";
import { toast } from "../ui/toast";

/** How often the console checks for a newer alarm. */
const POLL_MS = 5000;

const listeners = new Set<() => void>();

/** Every alarm read (the old list, the Alarms list, an alarm's page) starts with this. */
export const ALARMS_PREFIX = "/api/v1/alarm";

/** What a change refreshes at once: the old list, an alarm's page, suppressions. */
export const LIVE_PREFIXES = ["/api/v1/alarms", "/api/v1/alarm-suppressions"];

/** The Alarms list, refreshed by a change at most every `LIST_MS`. */
export const LIST_PREFIX = "/api/v1/alarm-list";
export const LIST_MS = 30_000;

/** When the list last refreshed, and whether a change since waits for it. */
type ListClock = { due: boolean; at: number };

/** Whether this poll (at `now`, the tab visible) refreshes the Alarms
 *  list: a change, or one held back earlier, once `LIST_MS` has passed. */
export function listRefresh(clock: ListClock, now: number, changed: boolean): { clock: ListClock; refresh: boolean } {
  const due = clock.due || changed;
  if (due && now - clock.at >= LIST_MS) return { clock: { due: false, at: now }, refresh: true };
  return { clock: { due, at: clock.at }, refresh: false };
}

/** Active alarms for the menu's count: up to 100 (`more` beyond). */
let active: { count: number; more: boolean } | undefined;
const setActive = (value: typeof active) => {
  active = value;
  for (const listener of listeners) listener();
};

/** The active-alarm count the poll keeps (undefined until the first answer). */
export function useActiveAlarms(): { count: number; more: boolean } | undefined {
  return useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, () => active);
}

/** Recounts active alarms (one page of 100), as a background request. */
async function recount(): Promise<void> {
  try {
    const page = await request<AlarmPage>("GET", "/api/v1/alarms?state=active&limit=100", undefined, { "X-OpenVIBES-Background": "1" });
    setActive({ count: page.items.length, more: Boolean(page.next_cursor) });
  } catch {
    // The next change tries again.
  }
}

/** What the poll remembers: the newest alarm's identity (for "did the
 *  list change") and the latest `first_seen` so far (for "is it new"). */
type Seen = { key: string | null; newest: string } | undefined;

/** Compares the newest-active alarm with what was seen before. `changed`:
 *  the list should refresh (anything moved, including the last alarm going
 *  away). `fresh`: an alarm that first appeared after everything seen so
 *  far; an older alarm repeating or resurfacing is not news. The first
 *  answer (`last` undefined) is the baseline and is never news. */
export function compareNewest(last: Seen, page: AlarmPage): { seen: Seen; changed: boolean; fresh: boolean } {
  const top = page.items[0];
  const key = top ? `${top.id}:${top.count}:${top.last_seen}` : null;
  if (last === undefined) return { seen: { key, newest: top?.first_seen ?? "" }, changed: false, fresh: false };
  // Compared as times: RFC 3339 strings with fractions of varying length
  // don't sort as text ("…:00.5Z" < "…:00Z").
  const fresh = top !== undefined && Date.parse(top.first_seen) > (Date.parse(last.newest) || 0);
  return { seen: { key, newest: fresh ? top.first_seen : last.newest }, changed: key !== last.key, fresh };
}

/** Polls while `enabled` and the page is visible. */
export function useLiveAlarms(enabled: boolean): void {
  useEffect(() => {
    if (!enabled) return;
    // The first answer is the baseline: only later changes are news.
    let last: Seen;
    // The list loaded with the page: its first live refresh is 30 s on.
    let list: ListClock = { due: false, at: Date.now() };
    let stopped = false;
    const poll = async () => {
      if (document.visibilityState !== "visible") return;
      try {
        // Marked as background: the poll must not keep an idle session alive.
        const page = await request<AlarmPage>("GET", "/api/v1/alarms?state=active&limit=1", undefined, { "X-OpenVIBES-Background": "1" });
        if (stopped) return;
        const first = last === undefined;
        const { seen, changed, fresh } = compareNewest(last, page);
        // The count changes only with the newest alarm (or its going away).
        if (first || changed) void recount();
        last = seen;
        if (changed) for (const prefix of LIVE_PREFIXES) invalidate(prefix);
        const step = listRefresh(list, Date.now(), changed);
        list = step.clock;
        if (step.refresh) invalidate(LIST_PREFIX);
        const top = page.items[0];
        if (fresh && top) {
          toast(`New alarm: ${top.message}${top.hostname ? ` on ${top.hostname}` : ""}`);
        }
      } catch {
        // Offline or signed out: the next poll tries again.
      }
    };
    void poll();
    const timer = window.setInterval(() => { void poll(); }, POLL_MS);
    // Triage elsewhere (resolving or quieting an older alarm) invalidates
    // the alarm lists without changing the newest: recount then too.
    let pending: number | undefined;
    const unsubscribe = subscribe(() => {
      window.clearTimeout(pending);
      pending = window.setTimeout(() => { void recount(); }, 300);
    });
    return () => { stopped = true; window.clearInterval(timer); window.clearTimeout(pending); unsubscribe(); };
  }, [enabled]);
}
