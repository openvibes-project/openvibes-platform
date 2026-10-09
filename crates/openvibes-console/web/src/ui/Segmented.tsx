// A button row for 2-4 choices: radiogroup, arrows move and wrap.
import { useRef } from "react";
import type { KeyboardEvent } from "react";

import { withUnknown, wrapStep } from "./segmented";

export function Segmented<T extends string | number>(props: {
  label: string;
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string }[];
  unknownLabel?: (v: T) => string;
}) {
  const { label, value, onChange, unknownLabel = String } = props;
  const options = withUnknown(props.options, value, unknownLabel);
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const current = options.findIndex((o) => o.value === value);

  const onKey = (e: KeyboardEvent) => {
    const delta = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
    if (!delta) return;
    e.preventDefault();
    const next = wrapStep(current, delta, options.length);
    const opt = options[next];
    if (opt) onChange(opt.value);
    refs.current[next]?.focus();
  };

  return (
    <div className="seg" role="radiogroup" aria-label={label} onKeyDown={onKey}>
      {options.map((o, i) => (
        <button
          key={String(o.value)}
          ref={(el) => { refs.current[i] = el; }}
          type="button"
          role="radio"
          aria-checked={i === current}
          tabIndex={i === current ? 0 : -1}
          className="seg__opt"
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
