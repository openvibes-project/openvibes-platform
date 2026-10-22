// A button row for 2-4 choices: radiogroup, arrows move and wrap, Home and End
// jump; an option may carry a suffix (a count).
import { useRef } from "react";
import type { KeyboardEvent, ReactNode } from "react";

import { keyTarget, withUnknown } from "./segmented";

export function Segmented<T extends string | number>(props: {
  label: string;
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string; suffix?: ReactNode }[];
  unknownLabel?: (v: T) => string;
}) {
  const { label, value, onChange, unknownLabel = String } = props;
  const options = withUnknown(props.options, value, unknownLabel);
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const current = options.findIndex((o) => o.value === value);

  const onKey = (e: KeyboardEvent) => {
    const next = keyTarget(e.key, current, options.length);
    if (next === null) return;
    e.preventDefault();
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
          tabIndex={i === current || (current < 0 && i === 0) ? 0 : -1}
          className="seg__opt"
          onClick={() => onChange(o.value)}
        >
          {o.label}{o.suffix !== undefined && <> <span className="subtle num">{o.suffix}</span></>}
        </button>
      ))}
    </div>
  );
}
