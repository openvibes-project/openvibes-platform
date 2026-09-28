// Widget gallery and per-widget settings, in the inspector beside the
// dashboard being edited.
import { nav } from "../app/nav";
import { Empty } from "../ui/bits";
import { Icon } from "../ui/Icon";
import { PanelHeader } from "../ui/panel";
import { editor, useEditor } from "./editor";
import { WIDGET_TYPES } from "./layout";
import { widgetDefs, widgetTitle } from "./widgets";

export function WidgetGalleryPanel() {
  const { draft } = useEditor();
  if (!draft) return <div className="panel-body"><Empty icon="overview" title="Not editing">Open one of your dashboards and choose Edit.</Empty></div>;
  return (
    <>
      <PanelHeader icon="plus" kind="Dashboard" title="Add widget" subtitle="Every widget shows only what your role can see, for whoever opens the dashboard." />
      <ul className="gallery">
        {WIDGET_TYPES.map((type) => {
          const def = widgetDefs[type];
          return (
            <li key={type}>
              <button type="button" className="gallery__item" onClick={() => { const id = editor.add(type); nav.open({ kind: "widget", id }, true); }}>
                <span className="attention__icon"><Icon name={def.icon} size={16} /></span>
                <span className="grow"><strong>{def.label}</strong><span className="subtle">{def.description}</span></span>
                <Icon name="plus" size={16} />
              </button>
            </li>
          );
        })}
      </ul>
    </>
  );
}

export function WidgetSettingsPanel({ id }: { id: string }) {
  const { draft } = useEditor();
  const widget = draft?.widgets.find((w) => w.id === id);
  if (!widget) return <div className="panel-body"><Empty icon="filter" title="No such widget">It was removed, or the dashboard is not being edited.</Empty></div>;
  const def = widgetDefs[widget.type];
  const title = typeof widget.config.title === "string" ? widget.config.title : "";
  return (
    <>
      <PanelHeader icon={def.icon} kind={def.label} title={widgetTitle(widget)} subtitle={def.description} />
      <div className="panel-body stack">
        <label className="field">Title<input className="input" maxLength={80} value={title} placeholder={widgetTitle({ ...widget, config: { ...widget.config, title: "" } })}
          onChange={(event) => editor.configure(id, { ...widget.config, title: event.target.value })} /></label>
        <def.Settings widget={widget} onChange={(config) => editor.configure(id, config)} />
        <div><button type="button" className="button button--danger button--small" onClick={() => { editor.remove(id); nav.closeAll(); }}><Icon name="close" size={14} /> Remove widget</button></div>
      </div>
    </>
  );
}
