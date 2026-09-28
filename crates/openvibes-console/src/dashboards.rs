//! Dashboards over `/api/v1`: layout validation (here) and the HTTP
//! handlers. A layout is data the UI renders; the server keeps it bounded
//! and well-formed, and forward-compatible through an allow-list of types.

use serde_json::Value;

use crate::FieldError;

pub(crate) const WIDGET_TYPES: [&str; 7] = [
    "number",
    "breakdown",
    "attention",
    "list",
    "trend",
    "top-hosts",
    "note",
];
const MAX_LAYOUT_BYTES: usize = 65_536;
const MAX_WIDGETS: usize = 40;
const MAX_ERRORS: usize = 32;

fn error(field: String, code: &str, message: &str) -> FieldError {
    FieldError {
        field,
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

pub(crate) fn validate_name(raw: &str) -> Result<String, FieldError> {
    let name = raw.trim();
    let count = name.chars().count();
    if count == 0 || count > 80 || name.chars().any(char::is_control) {
        return Err(error(
            "name".into(),
            "invalid_name",
            "Use 1 to 80 characters, without control characters",
        ));
    }
    Ok(name.to_owned())
}

fn int(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

fn valid_config_value(value: &Value) -> bool {
    match value {
        Value::String(text) => text.chars().count() <= 256,
        Value::Bool(_) => true,
        Value::Number(number) => number.is_i64(),
        Value::Array(items) => {
            items.len() <= 16
                && items.iter().all(|item| {
                    item.as_str()
                        .is_some_and(|text| text.chars().count() <= 256)
                })
        }
        _ => false,
    }
}

pub(crate) fn validate_layout(layout: &Value) -> Result<(), Vec<FieldError>> {
    let Some(object) = layout.as_object() else {
        return Err(vec![error(
            "layout".into(),
            "invalid_layout",
            "The layout must be an object",
        )]);
    };
    if serde_json::to_vec(layout).map_or(true, |bytes| bytes.len() > MAX_LAYOUT_BYTES) {
        return Err(vec![error(
            "layout".into(),
            "layout_too_large",
            "The layout exceeds 64 KiB",
        )]);
    }
    let mut errors = Vec::new();
    if object.get("schema").and_then(Value::as_i64) != Some(1) {
        errors.push(error(
            "layout.schema".into(),
            "unsupported_schema",
            "Layout schema must be 1",
        ));
    }
    let Some(widgets) = object.get("widgets").and_then(Value::as_array) else {
        errors.push(error(
            "layout.widgets".into(),
            "invalid_widgets",
            "widgets must be an array",
        ));
        return Err(errors);
    };
    if widgets.len() > MAX_WIDGETS {
        errors.push(error(
            "layout.widgets".into(),
            "too_many_widgets",
            "A dashboard holds at most 40 widgets",
        ));
        return Err(errors);
    }
    let mut seen = std::collections::HashSet::new();
    for (index, widget) in widgets.iter().enumerate() {
        let at = |field: &str| format!("layout.widgets[{index}].{field}");
        let Some(widget) = widget.as_object() else {
            errors.push(error(
                format!("layout.widgets[{index}]"),
                "invalid_widget",
                "A widget must be an object",
            ));
            continue;
        };
        let kind = widget.get("type").and_then(Value::as_str);
        if !kind.is_some_and(|kind| WIDGET_TYPES.contains(&kind)) {
            errors.push(error(
                at("type"),
                "unknown_widget_type",
                "Unknown widget type",
            ));
        }
        let id = widget.get("id").and_then(Value::as_str).unwrap_or_default();
        let id_ok = (1..=32).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !id_ok || !seen.insert(id.to_owned()) {
            errors.push(error(
                at("id"),
                "invalid_widget_id",
                "Widget ids are 1-32 of a-z, 0-9 and -, unique",
            ));
        }
        let (x, y, w, h) = (
            int(widget.get("x")),
            int(widget.get("y")),
            int(widget.get("w")),
            int(widget.get("h")),
        );
        let w_ok = w.is_some_and(|w| (1..=12).contains(&w));
        if !x.is_some_and(|x| (0..=11).contains(&x))
            || (w_ok && x.zip(w).is_some_and(|(x, w)| x + w > 12))
        {
            errors.push(error(
                at("x"),
                "invalid_position",
                "x must be 0-11 and x + w at most 12",
            ));
        }
        if !w_ok {
            errors.push(error(at("w"), "invalid_size", "w must be 1-12"));
        }
        if !y.is_some_and(|y| (0..=199).contains(&y)) {
            errors.push(error(at("y"), "invalid_position", "y must be 0-199"));
        }
        if !h.is_some_and(|h| (1..=12).contains(&h)) {
            errors.push(error(at("h"), "invalid_size", "h must be 1-12"));
        }
        match widget.get("config").and_then(Value::as_object) {
            None => errors.push(error(
                at("config"),
                "invalid_config",
                "config must be an object",
            )),
            Some(config) if config.len() > 16 => errors.push(error(
                at("config"),
                "invalid_config",
                "config holds at most 16 keys",
            )),
            Some(config) => {
                for (key, value) in config {
                    if key.len() > 32 || !valid_config_value(value) {
                        errors.push(error(
                            at(&format!("config.{key}")),
                            "invalid_config",
                            "Config values are short strings, integers, booleans or string lists",
                        ));
                    }
                }
            }
        }
    }
    errors.truncate(MAX_ERRORS);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{validate_layout, validate_name};

    fn widget(id: &str, kind: &str, x: i64, w: i64) -> serde_json::Value {
        json!({"id": id, "type": kind, "x": x, "y": 0, "w": w, "h": 2, "config": {"metric": "agents.active"}})
    }

    fn fields(layout: serde_json::Value) -> Vec<String> {
        validate_layout(&layout)
            .unwrap_err()
            .into_iter()
            .map(|error| error.field)
            .collect()
    }

    #[test]
    fn a_small_valid_layout_passes() {
        assert!(validate_layout(&json!({"schema": 1, "widgets": [widget("w1", "number", 0, 3), widget("w2", "note", 3, 9)]})).is_ok());
        assert!(validate_layout(&json!({"schema": 1, "widgets": []})).is_ok());
    }

    #[test]
    fn layout_must_be_an_object() {
        assert_eq!(fields(json!([1, 2])), ["layout"]);
        assert_eq!(fields(json!(7)), ["layout"]);
    }

    #[test]
    fn schema_widget_count_and_size_are_bounded() {
        assert_eq!(
            fields(json!({"schema": 2, "widgets": []})),
            ["layout.schema"]
        );
        let many: Vec<_> = (0..41)
            .map(|i| widget(&format!("w{i}"), "number", 0, 1))
            .collect();
        assert_eq!(
            fields(json!({"schema": 1, "widgets": many})),
            ["layout.widgets"]
        );
        let long = "x".repeat(256);
        let heavy: Vec<_> = (0..40)
            .map(|i| {
                json!({"id": format!("w{i}"), "type": "note", "x": 0, "y": 0, "w": 1, "h": 1,
            "config": {"text": vec![long.clone(); 7]}})
            })
            .collect();
        assert_eq!(fields(json!({"schema": 1, "widgets": heavy})), ["layout"]);
    }

    #[test]
    fn each_widget_is_checked_with_a_precise_path() {
        let layout = json!({"schema": 1, "widgets": [
            widget("w1", "pie-chart", 0, 3),
            widget("w1", "number", 10, 3),
            widget("Bad Id", "number", 0, 13),
            {"id": "w4", "type": "number", "x": 0, "y": 200, "w": 1, "h": 13, "config": {}},
            {"id": "w5", "type": "number", "x": 0, "y": 0, "w": 1, "h": 1, "config": {"nested": {"a": 1}}},
        ]});
        assert_eq!(
            fields(layout),
            [
                "layout.widgets[0].type",
                "layout.widgets[1].id",
                "layout.widgets[1].x",
                "layout.widgets[2].id",
                "layout.widgets[2].w",
                "layout.widgets[3].y",
                "layout.widgets[3].h",
                "layout.widgets[4].config.nested",
            ]
        );
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(validate_name("  Morning  ").unwrap(), "Morning");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"n".repeat(81)).is_err());
        assert!(validate_name("tab\there").is_err());
        assert_eq!(validate_name(&"é".repeat(80)).unwrap().chars().count(), 80);
    }
}
