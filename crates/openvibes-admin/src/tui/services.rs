//! The Services screen: the units, the selected unit's log, and the keys.
//! State is always written as text, so it reads without colour.

use platform_host::{Host, ServiceAction, ServiceStatus};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Row, Table},
};

use super::app::App;

const KEYS: &str = "Tab screens  j/k  s start  t stop  r restart  e/d boot  R refresh  q quit";

fn cells(status: &ServiceStatus) -> [String; 5] {
    let boot = match (status.installed, status.enabled) {
        (false, _) => "not installed",
        (true, true) => "enabled",
        (true, false) => "disabled",
    };
    let ready = match status.ready {
        Some(true) => "ready",
        Some(false) => "not ready",
        None => "-",
    };
    [
        status.unit.label().to_owned(),
        boot.to_owned(),
        if status.installed {
            status.active.clone()
        } else {
            "-".into()
        },
        ready.to_owned(),
        status.since.clone().unwrap_or_default(),
    ]
}

pub fn draw<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    let [table, logs, status, keys] = Layout::vertical([
        Constraint::Length(u16::try_from(app.services.len()).unwrap_or(5) + 3),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let rows = app.services.iter().enumerate().map(|(index, status)| {
        let row = Row::new(cells(status));
        if index == app.selected {
            row.style(Style::new().add_modifier(Modifier::REVERSED))
        } else {
            row
        }
    });
    let header = Row::new(["unit", "boot", "state", "ready", "since"])
        .style(Style::new().add_modifier(Modifier::BOLD));
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(14),
                Constraint::Length(14),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Min(10),
            ],
        )
        .header(header)
        .block(Block::new().borders(Borders::ALL).title(" units ")),
        table,
    );
    let unit = app
        .services
        .get(app.selected)
        .map_or("", |status| status.unit.name());
    let height = usize::from(logs.height.saturating_sub(2));
    let tail = app.logs.len().saturating_sub(height);
    let lines: Vec<Line> = app.logs[tail..]
        .iter()
        .map(|line| Line::raw(readable(line)))
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::new()
                .borders(Borders::ALL)
                .title(format!(" log: {unit} ")),
        ),
        logs,
    );
    let line = match (&app.boot, &app.confirm, &app.message) {
        (Some((unit, enable, prompt)), _, _) => format!(
            "{} {} at boot: your password: {}",
            if *enable { "Enable" } else { "Disable" },
            unit.name(),
            prompt.masked()
        ),
        (None, Some((unit, action)), _) => format!("{} {}? y/n", capitalised(*action), unit.name()),
        (None, None, Some(message)) => message.clone(),
        (None, None, None) => String::new(),
    };
    frame.render_widget(Paragraph::new(line), status);
    frame.render_widget(Paragraph::new(KEYS), keys);
}

fn capitalised(action: ServiceAction) -> &'static str {
    match action {
        ServiceAction::Start => "Start",
        ServiceAction::Stop => "Stop",
        ServiceAction::Restart => "Restart",
    }
}

/// A journal line (`short-iso`) as `HH:MM:SS LEVEL message key=value…`
/// (fields in key order) when the service logged tracing JSON (board #78: the raw JSON was hard
/// to read); any other line as it is.
pub(super) fn readable(line: &str) -> String {
    let Some(start) = line.find(": {") else {
        return line.to_owned();
    };
    let Ok(serde_json::Value::Object(event)) = serde_json::from_str(&line[start + 2..]) else {
        return line.to_owned();
    };
    // `2026-09-30T17:02:10+02:00 host unit[pid]:` → the local time.
    let time = line
        .split_whitespace()
        .next()
        .and_then(|stamp| stamp.split_once('T'))
        .map_or("", |(_, rest)| rest.get(..8).unwrap_or(rest));
    // Decoding turns a JSON escape like `\u001b` back into a real control
    // character, which ratatui would write to the terminal (reviewer on
    // #112): escape every decoded piece again.
    let text = |value: &serde_json::Value| {
        let raw = match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        safe(&raw)
    };
    let mut out = format!(
        "{time} {}",
        event.get("level").map(text).unwrap_or_default()
    );
    if let Some(serde_json::Value::Object(fields)) = event.get("fields") {
        if let Some(message) = fields.get("message") {
            out.push(' ');
            out.push_str(&text(message));
        }
        for (key, value) in fields.iter().filter(|(key, _)| *key != "message") {
            out.push_str(&format!(" {}={}", safe(key), text(value)));
        }
    }
    out
}

/// `text` with control characters escaped (`\u{1b}`), as the journal
/// reader does for the raw line.
fn safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::readable;

    /// Reviewer on #112: a log field can carry outside text; decoded, a
    /// JSON `\u001b` must not become a real escape sequence on screen.
    #[test]
    fn decoded_control_characters_stay_escaped() {
        let line = "2026-09-30T17:02:10+02:00 h openvibes-ingest[1]: \
                    {\"level\":\"WARN\",\"fields\":{\"message\":\"a\\u001b[31mb\",\
                    \"k\\u0007\":\"x\\u009b2J\"}}";
        let out = readable(line);
        assert!(!out.chars().any(char::is_control), "{out:?}");
        assert!(out.contains(r"a\u{1b}[31mb"), "{out:?}");
    }

    #[test]
    fn tracing_json_reads_as_one_short_line() {
        let line = "2026-09-30T17:02:10+02:00 metabox-lnx openvibes-ingest[3842528]: \
                    {\"timestamp\":\"2026-09-30T15:02:10.955489Z\",\"level\":\"INFO\",\
                    \"fields\":{\"message\":\"request\",\"endpoint\":\"/v1/heartbeat\",\
                    \"status\":204,\"latency_ms\":8},\"target\":\"platform_agent_server::limits\"}";
        assert_eq!(
            readable(line),
            "17:02:10 INFO request endpoint=/v1/heartbeat latency_ms=8 status=204"
        );
    }

    #[test]
    fn other_lines_are_left_alone() {
        for line in [
            "2026-09-30T17:02:10+02:00 metabox-lnx systemd[1]: Started openvibes-ingest.service.",
            "-- No entries --",
            "2026-09-30T17:02:10+02:00 h u[1]: {not json",
        ] {
            assert_eq!(readable(line), line);
        }
    }
}
