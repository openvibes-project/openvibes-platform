// One General row's editing, apart from React so it can be tested without a DOM:
// the typed text, whether a save is on its way, and what the last save said.
// A second commit while one is on its way (Enter, then the blur it causes) is ignored.
import { saveValue, type Saved } from "./General";

export type Send = (method: string, path: string, body?: unknown) => Promise<unknown>;

export function createRowEditor(key: string, initial: unknown, send: Send, notify: () => void, onSaved: () => void) {
  let current = initial;
  const state: { text: string | undefined; busy: boolean; result: Saved | undefined } = { text: undefined, busy: false, result: undefined };
  const save = async (value: unknown) => {
    if (state.busy) return;
    state.busy = true;
    state.result = undefined;
    notify();
    const result = await saveValue(key, value, send);
    state.busy = false;
    state.result = result;
    if (result.ok) { state.text = undefined; onSaved(); }
    notify(); // a refusal keeps the typed text
  };
  const editor = {
    state,
    /** The saved value, kept current by the row. */
    setValue(v: unknown) { current = v; },
    save,
    type(text: string) { state.text = text; state.result = undefined; notify(); },
    /** On blur or Enter: sends the typed number only when it differs from the saved one. */
    async commit() {
      const { text } = state;
      if (text === undefined || state.busy) return;
      if (text.trim() !== "" && Number(text) === current) { state.text = undefined; notify(); return; }
      await save(text.trim() === "" ? text : Number(text));
    },
  };
  return editor;
}
