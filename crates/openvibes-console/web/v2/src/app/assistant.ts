// Assistant state shared by the dock and every panel's "Ask about this".
// The conversation lives for the page; the dock's open state per viewer.
import { useSyncExternalStore } from "react";

import { ApiError, request } from "../api/client";
import type { AssistantReply, AssistantSegment } from "../api/types";
import type { PanelRef } from "./location";

export type Turn = {
  question: string;
  context: PanelRef | null;
  segments: AssistantSegment[] | undefined;
  error: string | undefined;
};

type State = { open: boolean; context: PanelRef | null; contextLabel: string | null; turns: Turn[]; busy: boolean };

const key = "openvibes.v2.assistant.open";
let state: State = { open: readOpen(), context: null, contextLabel: null, turns: [], busy: false };
const listeners = new Set<() => void>();

function readOpen() {
  try { return localStorage.getItem(key) === "true"; } catch { return false; }
}

function set(next: Partial<State>) {
  state = { ...state, ...next };
  if (next.open !== undefined) {
    try { localStorage.setItem(key, String(next.open)); } catch { /* per-viewer convenience only */ }
  }
  for (const listener of listeners) listener();
}

function flatten(segments: AssistantSegment[] | undefined): string {
  return (segments ?? []).map((segment) => segment.kind === "text" ? segment.text : `[${segment.target_kind}:${segment.id}]`).join("");
}

export const assistant = {
  toggle() { set({ open: !state.open }); },
  close() { set({ open: false }); },
  /** Opens the dock with an object as the context of the next question. */
  askAbout(context: PanelRef, label: string) { set({ open: true, context, contextLabel: label }); },
  clearContext() { set({ context: null, contextLabel: null }); },
  reset() { set({ turns: [], context: null, contextLabel: null }); },
  async ask(question: string) {
    const trimmed = question.trim();
    if (trimmed === "" || state.busy) return;
    const context = state.context;
    // The API takes plain text: the context travels as a leading note so the
    // server-side lookups can resolve the object it names.
    const sent = context ? `About ${context.kind} ${context.id} (${state.contextLabel ?? context.id}): ${trimmed}` : trimmed;
    const history = state.turns.filter((turn) => turn.segments).slice(-6).map((turn) => ({ question: turn.question, answer: flatten(turn.segments) }));
    const turn: Turn = { question: trimmed, context, segments: undefined, error: undefined };
    set({ turns: [...state.turns, turn], busy: true });
    try {
      const reply = await request<AssistantReply>("POST", "/api/v1/assistant/messages", { question: sent, history });
      turn.segments = reply.segments;
    } catch (error) {
      turn.error = error instanceof ApiError ? error.message : "The assistant is unavailable";
    }
    set({ turns: [...state.turns], busy: false });
  },
};

export function useAssistant(): State {
  return useSyncExternalStore((listener) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }, () => state);
}
