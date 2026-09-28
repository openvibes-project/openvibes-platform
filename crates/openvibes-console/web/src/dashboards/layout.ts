// Dashboard layouts: the same rules the server applies (the Rust module
// openvibes-console/src/dashboards.rs), so the editor can show problems
// before saving and the demo API refuses exactly what a console refuses.
export const WIDGET_TYPES = ["number", "breakdown", "attention", "list", "trend", "top-hosts", "note"] as const;
export type WidgetType = (typeof WIDGET_TYPES)[number];
export type ConfigValue = string | number | boolean | string[];
export type Widget = { id: string; type: WidgetType; x: number; y: number; w: number; h: number; config: Record<string, ConfigValue> };
export type Layout = { schema: 1; widgets: Widget[] };
export type FieldProblem = { field: string; code: string; message: string };

const MAX_BYTES = 65_536;
const MAX_WIDGETS = 40;
const problem = (field: string, code: string, message: string): FieldProblem => ({ field, code, message });
const isInt = (value: unknown): value is number => typeof value === "number" && Number.isInteger(value);
const chars = (text: string) => [...text].length;
const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value)).length;

export function validateName(raw: string): string | FieldProblem {
  const name = raw.trim();
  // eslint-disable-next-line no-control-regex
  if (chars(name) === 0 || chars(name) > 80 || /[\u0000-\u001f\u007f-\u009f]/.test(name)) {
    return problem("name", "invalid_name", "Use 1 to 80 characters, without control characters");
  }
  return name;
}

function validConfigValue(value: unknown): boolean {
  if (typeof value === "string") return chars(value) <= 256;
  if (typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isInteger(value);
  return Array.isArray(value) && value.length <= 16 && value.every((item) => typeof item === "string" && chars(item) <= 256);
}

export function validateLayout(layout: unknown): FieldProblem[] {
  if (typeof layout !== "object" || layout === null || Array.isArray(layout)) return [problem("layout", "invalid_layout", "The layout must be an object")];
  if (bytes(layout) > MAX_BYTES) return [problem("layout", "layout_too_large", "The layout exceeds 64 KiB")];
  const object = layout as Record<string, unknown>;
  const problems: FieldProblem[] = [];
  if (object.schema !== 1) problems.push(problem("layout.schema", "unsupported_schema", "Layout schema must be 1"));
  const widgets = object.widgets;
  if (!Array.isArray(widgets)) return [...problems, problem("layout.widgets", "invalid_widgets", "widgets must be an array")];
  if (widgets.length > MAX_WIDGETS) return [...problems, problem("layout.widgets", "too_many_widgets", "A dashboard holds at most 40 widgets")];
  const seen = new Set<string>();
  widgets.forEach((raw, index) => {
    const at = (field: string) => `layout.widgets[${index}].${field}`;
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      problems.push(problem(`layout.widgets[${index}]`, "invalid_widget", "A widget must be an object"));
      return;
    }
    const widget = raw as Record<string, unknown>;
    if (!(WIDGET_TYPES as readonly unknown[]).includes(widget.type)) problems.push(problem(at("type"), "unknown_widget_type", "Unknown widget type"));
    const id = typeof widget.id === "string" ? widget.id : "";
    if (!/^[a-z0-9-]{1,32}$/.test(id) || seen.has(id)) problems.push(problem(at("id"), "invalid_widget_id", "Widget ids are 1-32 of a-z, 0-9 and -, unique"));
    seen.add(id);
    const { x, y, w, h } = widget;
    const wOk = isInt(w) && w >= 1 && w <= 12;
    if (!(isInt(x) && x >= 0 && x <= 11) || (wOk && isInt(x) && x + w > 12)) problems.push(problem(at("x"), "invalid_position", "x must be 0-11 and x + w at most 12"));
    if (!wOk) problems.push(problem(at("w"), "invalid_size", "w must be 1-12"));
    if (!(isInt(y) && y >= 0 && y <= 199)) problems.push(problem(at("y"), "invalid_position", "y must be 0-199"));
    if (!(isInt(h) && h >= 1 && h <= 12)) problems.push(problem(at("h"), "invalid_size", "h must be 1-12"));
    const config = widget.config;
    if (typeof config !== "object" || config === null || Array.isArray(config)) {
      problems.push(problem(at("config"), "invalid_config", "config must be an object"));
    } else if (Object.keys(config).length > 16) {
      problems.push(problem(at("config"), "invalid_config", "config holds at most 16 keys"));
    } else {
      for (const [key, value] of Object.entries(config)) {
        if (key.length > 32 || !validConfigValue(value)) problems.push(problem(at(`config.${key}`), "invalid_config", "Config values are short strings, integers, booleans or string lists"));
      }
    }
  });
  return problems.slice(0, 32);
}

export const COLUMNS = 12;
export const ROW_HEIGHT = 56;
const clamp = (value: number, low: number, high: number) => Math.min(high, Math.max(low, Math.round(value)));

export function overlaps(a: Widget, b: Widget): boolean {
  return a.id !== b.id && a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

/** Keeps `fixedId` in place and moves every colliding tile straight down,
 *  top to bottom, so no two tiles overlap. Input order is preserved. */
export function settle(widgets: readonly Widget[], fixedId: string): Widget[] {
  const fixed = widgets.find((w) => w.id === fixedId);
  if (!fixed) return [...widgets];
  const placed: Widget[] = [fixed];
  const others = widgets.filter((w) => w.id !== fixedId).sort((a, b) => a.y - b.y || a.x - b.x);
  const moved = new Map<string, Widget>([[fixed.id, fixed]]);
  for (const widget of others) {
    let candidate = widget;
    while (placed.some((p) => overlaps(candidate, p)) && candidate.y < 199) candidate = { ...candidate, y: candidate.y + 1 };
    placed.push(candidate);
    moved.set(candidate.id, candidate);
  }
  return widgets.map((w) => moved.get(w.id) ?? w);
}

export function moveWidget(layout: Layout, id: string, x: number, y: number): Layout {
  const widgets = layout.widgets.map((w) => w.id === id ? { ...w, x: clamp(x, 0, COLUMNS - w.w), y: clamp(y, 0, 199) } : w);
  return { ...layout, widgets: settle(widgets, id) };
}

export function resizeWidget(layout: Layout, id: string, w: number, h: number): Layout {
  const widgets = layout.widgets.map((widget) => widget.id === id ? { ...widget, w: clamp(w, 1, COLUMNS - widget.x), h: clamp(h, 1, 12) } : widget);
  return { ...layout, widgets: settle(widgets, id) };
}

export function addWidget(layout: Layout, type: WidgetType, size: { w: number; h: number }, config: Widget["config"]): { layout: Layout; id: string } {
  let n = 1;
  while (layout.widgets.some((w) => w.id === `${type}-${n}`)) n += 1;
  const id = `${type}-${n}`;
  const bottom = layout.widgets.reduce((max, w) => Math.max(max, w.y + w.h), 0);
  const widget: Widget = { id, type, x: 0, y: Math.min(bottom, 199), w: Math.min(size.w, COLUMNS), h: size.h, config };
  return { layout: { ...layout, widgets: [...layout.widgets, widget] }, id };
}

export function removeWidget(layout: Layout, id: string): Layout {
  return { ...layout, widgets: layout.widgets.filter((w) => w.id !== id) };
}

export function readingOrder(widgets: readonly Widget[]): Widget[] {
  return [...widgets].sort((a, b) => a.y - b.y || a.x - b.x);
}
