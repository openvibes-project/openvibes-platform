// Alarms show up without a reload: while the console is visible it asks
// for the newest active alarm every few seconds. When that changes, alarm
// views refresh, a new alarm gets a toast, and the rail marks Alarms until
// it is opened. One small request per poll; no websocket.
import { useEffect, useRef, useSyncExternalStore } from "react";

import { invalidate, request } from "../api/client";
import type { AlarmPage } from "../api/types";
import { toast } from "../ui/toast";

/** How often the console checks for a newer alarm. */
export const POLL_MS = 5000;

let unseen = false;
const listeners = new Set<() => void>();
const setUnseen = (value: boolean) => {
  if (unseen === value) return;
  unseen = value;
  for (const listener of listeners) listener();
};

/** True when an alarm arrived since Alarms was last open. */
export function useUnseenAlarms(): boolean {
  return useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, () => unseen);
}

type Seen = { id: string; key: string } | null | undefined;

/** Compares the newest alarm with the last one seen: `changed` when the
 *  list should refresh, `fresh` when it is a new alarm (not a repeat). The
 *  first answer (`last` undefined) is the baseline and is never news. */
export function compareNewest(last: Seen, page: AlarmPage): { seen: Seen; changed: boolean; fresh: boolean } {
  const top = page.items[0];
  const seen = top ? { id: top.id, key: `${top.id}:${top.count}:${top.last_seen}` } : null;
  const changed = last !== undefined && seen !== null && seen.key !== last?.key;
  return { seen, changed, fresh: changed && seen?.id !== last?.id };
}

/** Polls while `enabled` and the page is visible; `onAlarms` clears the mark. */
export function useLiveAlarms(enabled: boolean, onAlarms: boolean): void {
  // A ref, so moving between views keeps the poll and its baseline.
  const viewing = useRef(onAlarms);
  useEffect(() => { viewing.current = onAlarms; if (onAlarms) setUnseen(false); }, [onAlarms]);
  useEffect(() => {
    if (!enabled) return;
    // The first answer is the baseline: only later changes are news.
    let last: Seen;
    let stopped = false;
    const poll = async () => {
      if (document.visibilityState !== "visible") return;
      try {
        const page = await request<AlarmPage>("GET", "/api/v1/alarms?state=active&limit=1");
        if (stopped) return;
        const { seen, changed, fresh } = compareNewest(last, page);
        last = seen;
        if (changed) invalidate("/api/v1/alarms");
        const top = page.items[0];
        if (fresh && top) {
          toast(`New alarm: ${top.message}${top.hostname ? ` on ${top.hostname}` : ""}`);
          if (!viewing.current) setUnseen(true);
        }
      } catch {
        // Offline or signed out: the next poll tries again.
      }
    };
    void poll();
    const timer = window.setInterval(() => { void poll(); }, POLL_MS);
    return () => { stopped = true; window.clearInterval(timer); };
  }, [enabled]);
}
