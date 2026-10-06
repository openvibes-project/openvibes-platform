// Agent online/offline changes arrive without a reload: the server holds a
// small event stream open and says when the online set changed (an agent
// came online or went offline). Agent views then refetch through the usual
// API calls, so the stream carries no agent data. Read with fetch rather
// than EventSource so the request can be marked as background (it must not
// keep an idle session alive); the server closes it every minute and it
// reconnects, which re-checks the session too.
import { useEffect } from "react";

import { inDemo, invalidate } from "../api/client";

/** Least time between two refetches, however fast changes arrive. */
export const MIN_REFRESH_MS = 2000;
/** Wait before reconnecting after the stream ends or fails. */
export const RECONNECT_MS = 3000;

/** Reads event-stream text and calls `onEvent` for each `presence` event.
 *  Returns what is left of an unfinished line, to prepend to the next chunk. */
export function parseEvents(buffer: string, onEvent: () => void): string {
  let rest = buffer;
  for (let end = rest.indexOf("\n\n"); end !== -1; end = rest.indexOf("\n\n")) {
    const block = rest.slice(0, end);
    rest = rest.slice(end + 2);
    if (block.split("\n").includes("event: presence")) onEvent();
  }
  return rest;
}

/** Keeps agent views fresh while `enabled` and the page is visible. */
export function useLivePresence(enabled: boolean): void {
  useEffect(() => {
    if (!enabled || inDemo()) return;
    let stopped = false;
    let abort: AbortController | undefined;
    let last = 0;
    let pending: number | undefined;
    const refresh = () => {
      const wait = Math.max(0, last + MIN_REFRESH_MS - Date.now());
      if (pending !== undefined) return;
      pending = window.setTimeout(() => {
        pending = undefined;
        last = Date.now();
        invalidate("/api/v1/agents");
      }, wait);
    };
    const run = async () => {
      while (!stopped) {
        if (document.visibilityState === "visible") {
          abort = new AbortController();
          try {
            const response = await fetch("/api/v1/agents/events", {
              cache: "no-store",
              credentials: "same-origin",
              headers: { accept: "text/event-stream", "x-openvibes-background": "1" },
              signal: abort.signal,
            });
            // Signed out or not allowed: stop; the session check elsewhere shows it.
            if (response.status === 401 || response.status === 403) return;
            if (response.ok && response.body) {
              // Anything may have changed while the stream was down.
              refresh();
              const reader = response.body.getReader();
              const decoder = new TextDecoder();
              let buffer = "";
              for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer = parseEvents(buffer + decoder.decode(value, { stream: true }), refresh);
              }
            }
          } catch {
            // Offline or reset: reconnect below.
          }
        }
        if (!stopped) await new Promise((resolve) => window.setTimeout(resolve, RECONNECT_MS));
      }
    };
    void run();
    return () => { stopped = true; abort?.abort(); window.clearTimeout(pending); };
  }, [enabled]);
}
