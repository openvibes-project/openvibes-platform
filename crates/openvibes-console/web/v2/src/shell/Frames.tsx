// The window-in-window frames: the inspector (a stack of panels beside the
// list, with a breadcrumb) and floating windows popped out of it.
import { type PointerEvent as ReactPointerEvent, useEffect, useRef, useState } from "react";

import type { PanelRef } from "../app/location";
import { nav, useLocation } from "../app/nav";
import { panels } from "../app/registry";
import { type Win, useWindows, windowsStore } from "../app/windows";
import { Empty } from "../ui/bits";
import { Icon } from "../ui/Icon";

function PanelContent({ panel }: { panel: PanelRef }) {
  const def = panels[panel.kind];
  if (!def) return <Empty icon="alert" title="Unknown object">This link points to something the console cannot show.</Empty>;
  return <>{def.render(panel.id)}</>;
}

const widthKey = "openvibes.v2.inspector.width";
function readWidth() {
  try { return Number(localStorage.getItem(widthKey)) || 520; } catch { return 520; }
}

export function Inspector() {
  const { panels: stack } = useLocation();
  const [width, setWidth] = useState(readWidth);
  const [wide, setWide] = useState(false);
  const top = stack[stack.length - 1];
  const scroller = useRef<HTMLDivElement>(null);

  useEffect(() => { scroller.current?.scrollTo({ top: 0 }); }, [top?.kind, top?.id]);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || stack.length === 0) return;
      const target = event.target as HTMLElement;
      if (target.closest(".palette, .assistant, .window") || (target instanceof HTMLInputElement && target.value !== "")) return;
      nav.back();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [stack.length]);

  if (!top) return null;
  const startResize = (event: ReactPointerEvent) => {
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = width;
    const onMove = (move: PointerEvent) => setWidth(Math.min(Math.max(380, startWidth + startX - move.clientX), window.innerWidth - 360));
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      setWidth((current) => { try { localStorage.setItem(widthKey, String(current)); } catch { /* per viewer */ } return current; });
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  };

  return (
    <aside className={wide ? "inspector inspector--wide" : "inspector"} style={wide ? undefined : { width }} aria-label="Details">
      <div className="inspector__resize" onPointerDown={startResize} role="separator" aria-orientation="vertical" aria-label="Resize details" />
      <div className="frame-bar">
        {stack.length > 1 && (
          <button type="button" className="icon-button" aria-label="Back" title="Back (Esc)" onClick={() => nav.back()}><Icon name="back" size={16} /></button>
        )}
        <nav className="crumbs" aria-label="Opened objects">
          {stack.map((panel, index) => {
            const def = panels[panel.kind];
            const last = index === stack.length - 1;
            return (
              <span key={`${panel.kind}:${panel.id}`} className="crumbs__item">
                {index > 0 && <Icon name="chevronRight" size={12} className="subtle" />}
                {last ? <span className="crumbs__current truncate" aria-current="page">{def?.title(panel.id) ?? panel.id}</span>
                  : <button type="button" className="crumbs__link truncate" onClick={() => nav.truncate(index + 1)}>{def?.title(panel.id) ?? panel.id}</button>}
              </span>
            );
          })}
        </nav>
        <div className="frame-bar__actions">
          <button type="button" className="icon-button" aria-label="Open in a window" title="Pop out into a window" onClick={() => windowsStore.popOut(top)}><Icon name="popout" size={16} /></button>
          <button type="button" className="icon-button" aria-pressed={wide} aria-label={wide ? "Restore width" : "Maximise"} title={wide ? "Restore width" : "Maximise"} onClick={() => setWide((w) => !w)}><Icon name="maximize" size={16} /></button>
          <button type="button" className="icon-button" aria-label="Close details" title="Close all (Esc closes one)" onClick={() => nav.closeAll()}><Icon name="close" size={16} /></button>
        </div>
      </div>
      <div className="inspector__scroll" ref={scroller} key={`${top.kind}:${top.id}`}>
        <PanelContent panel={top} />
      </div>
    </aside>
  );
}

function FloatingWindow({ win }: { win: Win }) {
  const def = panels[win.kind];
  const drag = (event: ReactPointerEvent, mode: "move" | "resize") => {
    if ((event.target as HTMLElement).closest("button") && mode === "move") return;
    event.preventDefault();
    windowsStore.focus(win);
    const start = { x: event.clientX, y: event.clientY, wx: win.x, wy: win.y, ww: win.w, wh: win.h };
    const onMove = (move: PointerEvent) => {
      const dx = move.clientX - start.x;
      const dy = move.clientY - start.y;
      if (mode === "move") windowsStore.move(win, start.wx + dx, start.wy + dy);
      else windowsStore.resize(win, start.ww + dx, start.wh + dy);
    };
    const onUp = () => { window.removeEventListener("pointermove", onMove); window.removeEventListener("pointerup", onUp); };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  };
  if (win.min) return null;
  return (
    <section className="window" style={{ left: win.x, top: win.y, width: win.w, height: win.h, zIndex: win.z }}
      aria-label={`${def?.label ?? "Window"}: ${def?.title(win.id) ?? win.id}`} onPointerDown={() => windowsStore.focus(win)}
      onKeyDown={(event) => { if (event.key === "Escape") windowsStore.close(win); }}>
      <div className="window__bar" onPointerDown={(event) => drag(event, "move")}>
        <Icon name={def?.icon ?? "layers"} size={14} className="subtle" />
        <span className="window__title truncate">{def?.label}: {def?.title(win.id) ?? win.id}</span>
        <button type="button" className="icon-button" aria-label="Minimise" onClick={() => windowsStore.minimize(win)}><Icon name="minimize" size={14} /></button>
        <button type="button" className="icon-button" aria-label="Back into the details pane" title="Dock into the details pane" onClick={() => windowsStore.dock(win)}><Icon name="dock" size={14} /></button>
        <button type="button" className="icon-button" aria-label="Close window" onClick={() => windowsStore.close(win)}><Icon name="close" size={14} /></button>
      </div>
      <div className="window__body"><PanelContent panel={win} /></div>
      <div className="window__grip" onPointerDown={(event) => drag(event, "resize")} aria-hidden="true" />
    </section>
  );
}

export function WindowLayer() {
  const windows = useWindows();
  const minimized = windows.filter((w) => w.min);
  return (
    <>
      {windows.map((win) => <FloatingWindow key={`${win.kind}:${win.id}`} win={win} />)}
      {minimized.length > 0 && (
        <div className="window-dock" role="toolbar" aria-label="Minimised windows">
          {minimized.map((win) => {
            const def = panels[win.kind];
            return (
              <button key={`${win.kind}:${win.id}`} type="button" className="window-dock__item" onClick={() => windowsStore.focus(win)}>
                <Icon name={def?.icon ?? "layers"} size={14} /> <span className="truncate">{def?.title(win.id) ?? win.id}</span>
              </button>
            );
          })}
        </div>
      )}
    </>
  );
}
