// A row of count chips that picks one segment ("All 12", "Web 3"): a radio
// group; arrows move and select (wrapping), Home and End jump, one tab stop.
// Same look as Segmented (ui/Segmented.tsx), plus a count after each label.
import { useRef } from "react";
import type { KeyboardEvent } from "react";

import { wrapStep } from "../segmented";

/** The index a key moves to, or null when the key is not ours. */
export function chipTarget(key: string, current: number, count: number): number | null {
  if (key === "ArrowRight" || key === "ArrowDown") return wrapStep(current, 1, count);
  if (key === "ArrowLeft" || key === "ArrowUp") return wrapStep(current, -1, count);
  if (key === "Home") return 0;
  if (key === "End") return count - 1;
  return null;
}

export function SegmentChips(props: Readonly<{
  label: string;
  options: { key: string; label: string; count: number }[];
  value: string;
  onChange: (key: string) => void;
}>) {
  const { label, options, value, onChange } = props;
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const current = options.findIndex((o) => o.key === value);

  const onKey = (e: KeyboardEvent) => {
    const next = chipTarget(e.key, current, options.length);
    if (next === null) return;
    e.preventDefault();
    const opt = options[next];
    if (opt) onChange(opt.key);
    refs.current[next]?.focus();
  };

  return (
    <div className="seg" role="radiogroup" aria-label={label} onKeyDown={onKey}>
      {options.map((o, i) => (
        <button
          key={o.key}
          ref={(el) => { refs.current[i] = el; }}
          type="button"
          role="radio"
          aria-checked={i === current}
          tabIndex={i === current || (current < 0 && i === 0) ? 0 : -1}
          className="seg__opt"
          onClick={() => onChange(o.key)}
        >
          {o.label} <span className="subtle num">{o.count.toLocaleString()}</span>
        </button>
      ))}
    </div>
  );
}
