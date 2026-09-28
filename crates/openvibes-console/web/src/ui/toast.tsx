import { useSyncExternalStore } from "react";

import { Icon } from "./Icon";

type Toast = { id: number; text: string; bad: boolean };
let toasts: Toast[] = [];
let next = 1;
const listeners = new Set<() => void>();
const emit = () => { for (const listener of listeners) listener(); };

export function toast(text: string, bad = false): void {
  const id = next++;
  toasts = [...toasts, { id, text, bad }];
  emit();
  setTimeout(() => { toasts = toasts.filter((item) => item.id !== id); emit(); }, bad ? 7000 : 3500);
}

export function Toasts() {
  const items = useSyncExternalStore((listener) => { listeners.add(listener); return () => listeners.delete(listener); }, () => toasts);
  return (
    <div className="toasts" role="status" aria-live="polite">
      {items.map((item) => (
        <div key={item.id} className={item.bad ? "toast toast--bad" : "toast"}>
          <Icon name={item.bad ? "alert" : "check"} size={16} /> {item.text}
        </div>
      ))}
    </div>
  );
}
