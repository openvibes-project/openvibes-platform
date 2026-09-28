// Dashboard tiles on a 12-column grid. View mode never moves anything; in
// edit mode headers drag, corners resize, and a focused tile answers the
// keyboard. Each tile has its own error boundary.
import { Component, type KeyboardEvent, type PointerEvent as ReactPointerEvent, type ReactNode, useEffect, useRef, useState } from "react";

import { nav } from "../app/nav";
import { Icon } from "../ui/Icon";
import { editor, useEditor } from "./editor";
import { COLUMNS, type Layout, ROW_HEIGHT, type Widget, moveWidget, readingOrder, resizeWidget } from "./layout";
import { widgetDefs, widgetTitle } from "./widgets";

class TileBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  override state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  override render() {
    return this.state.failed ? <div className="tile-empty"><Icon name="alert" size={18} /> This tile failed to show</div> : this.props.children;
  }
}

const GAP = 12;

export function Grid({ layout, editing }: { layout: Layout; editing: boolean }) {
  const { selected } = useEditor();
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(1200);
  useEffect(() => {
    if (!box.current) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry?.contentRect.width ?? 1200));
    observer.observe(box.current);
    return () => observer.disconnect();
  }, []);
  const phone = width < 720;
  const column = (width + GAP) / COLUMNS;
  // A layout from another console version may lack widgets or hold types this
  // build does not know; neither may take the dashboard (or the app) down.
  const widgets = Array.isArray(layout?.widgets) ? layout.widgets : [];
  const height = widgets.reduce((max, w) => Math.max(max, w.y + w.h), 0) * ROW_HEIGHT;
  const canEdit = editing && !phone;

  const drag = (event: ReactPointerEvent, widget: Widget, mode: "move" | "resize") => {
    if (!canEdit || (mode === "move" && (event.target as HTMLElement).closest("button"))) return;
    event.preventDefault();
    editor.select(widget.id);
    const start = { x: event.clientX, y: event.clientY };
    const onMove = (move: PointerEvent) => {
      const dx = Math.round((move.clientX - start.x) / column);
      const dy = Math.round((move.clientY - start.y) / ROW_HEIGHT);
      const draft = editor.state().draft ?? layout;
      editor.change(mode === "move" ? moveWidget(draft, widget.id, widget.x + dx, widget.y + dy) : resizeWidget(draft, widget.id, widget.w + dx, widget.h + dy));
    };
    const onUp = () => { window.removeEventListener("pointermove", onMove); window.removeEventListener("pointerup", onUp); };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  };

  const onKey = (event: KeyboardEvent, widget: Widget) => {
    if (!canEdit || event.target !== event.currentTarget) return;
    const step: Record<string, [number, number]> = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
    const delta = step[event.key];
    const draft = editor.state().draft ?? layout;
    if (delta) {
      event.preventDefault();
      editor.change(event.shiftKey ? resizeWidget(draft, widget.id, widget.w + delta[0], widget.h + delta[1]) : moveWidget(draft, widget.id, widget.x + delta[0], widget.y + delta[1]));
    } else if (event.key === "Delete" || event.key === "Backspace") {
      event.preventDefault();
      editor.remove(widget.id);
    } else if (event.key === "Enter") {
      nav.open({ kind: "widget", id: widget.id }, true);
    }
  };

  const tiles = phone ? readingOrder(widgets) : widgets;
  return (
    <div ref={box} className={phone ? "grid grid--stacked" : canEdit ? "grid grid--editing" : "grid"} style={phone ? undefined : { height }}>
      {tiles.map((widget) => {
        const Def = (widgetDefs as Partial<Record<string, (typeof widgetDefs)[keyof typeof widgetDefs]>>)[widget.type];
        const title = widgetTitle(widget);
        const style = phone ? undefined : {
          left: widget.x * column, top: widget.y * ROW_HEIGHT,
          width: widget.w * column - GAP, height: widget.h * ROW_HEIGHT - GAP,
        };
        return (
          <section key={widget.id} className="tile" style={style} aria-label={title} data-selected={canEdit && selected === widget.id || undefined}
            tabIndex={canEdit ? 0 : undefined} aria-describedby={canEdit ? "grid-keys" : undefined} onKeyDown={(event) => onKey(event, widget)} onFocus={() => canEdit && editor.select(widget.id)}>
            <header className="tile__head" onPointerDown={(event) => drag(event, widget, "move")}>
              <h2 className="tile__title truncate">{title}</h2>
              {canEdit && (
                <span className="row">
                  <button type="button" className="icon-button" aria-label={`Settings for ${title}`} onClick={() => nav.open({ kind: "widget", id: widget.id }, true)}><Icon name="filter" size={14} /></button>
                  <button type="button" className="icon-button" aria-label={`Remove ${title}`} onClick={() => editor.remove(widget.id)}><Icon name="close" size={14} /></button>
                </span>
              )}
            </header>
            <div className="tile__body"><TileBoundary>{Def ? <Def.View widget={widget} /> : <div className="tile-empty"><Icon name="alert" size={18} /> This widget needs a newer console ({String(widget.type)})</div>}</TileBoundary></div>
            {canEdit && <span className="tile__grip" onPointerDown={(event) => drag(event, widget, "resize")} aria-hidden="true" />}
          </section>
        );
      })}
      {canEdit && <p id="grid-keys" className="sr-only">Arrow keys move this tile, Shift and arrow keys resize it, Delete removes it (Undo appears above), Enter opens its settings.</p>}
      {widgets.length === 0 && <div className="tile-empty grid__empty"><Icon name="plus" size={18} /> {editing ? "Add a widget to start." : "This dashboard is empty."}</div>}
    </div>
  );
}
