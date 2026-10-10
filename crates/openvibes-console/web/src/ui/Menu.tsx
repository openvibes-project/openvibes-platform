// A menu button: a button that opens a short list of actions (not a value
// picker; that is Select). Same popup look and placement as Select, full
// keyboard use: arrows move, Enter picks, Escape closes (#253).
import { type CSSProperties, type KeyboardEvent, useEffect, useId, useLayoutEffect, useRef, useState } from "react";

import { Icon, type IconName } from "./Icon";
import { placement } from "./select";

export type MenuItem = { value: string; label: string; description?: string; dot?: string };

export function MenuButton({ label, icon, items, onPick, disabled }: Readonly<{
  label: string; icon?: IconName; items: MenuItem[]; onPick: (value: string) => void; disabled?: boolean;
}>) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [box, setBox] = useState<CSSProperties>();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const id = useId();

  const close = (restore = false) => { setOpen(false); if (restore) button.current?.focus(); };
  const place = () => {
    if (!button.current) return;
    const rect = button.current.getBoundingClientRect();
    const box = placement(rect, { width: window.innerWidth, height: window.innerHeight });
    setBox({ position: "fixed", ...box, width: Math.min(300, window.innerWidth - 16) });
  };
  useLayoutEffect(() => { if (open) place(); }, [open]);
  useEffect(() => {
    if (!open) return;
    list.current?.focus({ preventScroll: true });
    const away = (event: PointerEvent) => { if (!root.current?.contains(event.target as Node)) close(); };
    const moved = () => close();
    document.addEventListener("pointerdown", away);
    window.addEventListener("scroll", moved, true);
    window.addEventListener("resize", moved);
    return () => {
      document.removeEventListener("pointerdown", away);
      window.removeEventListener("scroll", moved, true);
      window.removeEventListener("resize", moved);
    };
  }, [open]);

  const pick = (item: MenuItem | undefined) => {
    if (!item) return;
    close(true);
    onPick(item.value);
  };
  const onKey = (event: KeyboardEvent) => {
    if (event.key === "ArrowDown") { event.preventDefault(); setActive((i) => Math.min(items.length - 1, i + 1)); }
    else if (event.key === "ArrowUp") { event.preventDefault(); setActive((i) => Math.max(0, i - 1)); }
    else if (event.key === "Enter" || event.key === " ") { event.preventDefault(); pick(items[active]); }
    else if (event.key === "Escape") { event.stopPropagation(); close(true); }
    else if (event.key === "Tab") close();
  };

  return (
    <div className="sel" ref={root}>
      <button ref={button} type="button" className="button menu-button" aria-haspopup="menu" aria-expanded={open} aria-controls={open ? id : undefined}
        disabled={disabled}
        onClick={() => { setActive(0); setOpen(!open); }}
        onKeyDown={(event) => { if (event.key === "ArrowDown") { event.preventDefault(); setActive(0); setOpen(true); } }}>
        {icon && <Icon name={icon} size={15} />}{label}<Icon name="chevronDown" size={14} />
      </button>
      {open && (
        <div className="sel__popup" style={box}>
          <div className="sel__list" role="menu" id={id} aria-label={label} ref={list} tabIndex={-1} onKeyDown={onKey}
            aria-activedescendant={`${id}-${active}`}>
            {items.map((item, i) => (
              <div key={item.value} id={`${id}-${i}`} role="menuitem" tabIndex={-1}
                className={i === active ? "sel__option sel__option--active menu-option" : "sel__option menu-option"}
                onPointerEnter={() => setActive(i)} onClick={() => pick(item)}
                onKeyDown={(event) => { if (event.key === "Enter") pick(item); }}>
                <span className="menu-option__dot" style={item.dot ? { background: item.dot } : undefined} aria-hidden="true" />
                <span className="menu-option__text"><span>{item.label}</span>{item.description && <span className="subtle">{item.description}</span>}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

