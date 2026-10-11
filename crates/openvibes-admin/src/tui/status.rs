//! Status (spec §4): what needs attention first, then the installed
//! services (name, state, ready, since), then the checks that are fine.
//! The line under the list gives the highlighted problem or check in
//! full. There is no boot switch: a unit not enabled at boot is a problem whose Enter
//! fixes it.

use platform_host::{Host, ServiceStatus, Unit};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    app::{App, Key},
    database::Check,
    nav::Screen,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fix {
    Start(Unit),
    Enable(Unit),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Item {
    Problem {
        text: String,
        fix: Option<Fix>,
    },
    Service(Unit),
    /// A health check that is fine.
    Check(String),
}

/// Idle by design while stopped: the model server starts on use, the
/// maintenance timer's service between runs.
fn idles(unit: Unit) -> bool {
    matches!(unit, Unit::Llm | Unit::Maintenance)
}

/// Unit problems, then health problems, then the installed services, then
/// the checks that are fine.
pub fn items(services: &[ServiceStatus], checks: &[Check]) -> Vec<Item> {
    let installed = || services.iter().filter(|s| s.installed);
    let mut out = Vec::new();
    for s in installed() {
        if !idles(s.unit) && matches!(s.active.as_str(), "failed" | "inactive") {
            out.push(Item::Problem {
                text: format!("{} is stopped", s.unit.label()),
                fix: Some(Fix::Start(s.unit)),
            });
        } else if !s.enabled {
            out.push(Item::Problem {
                text: format!("{} does not start at boot", s.unit.label()),
                fix: Some(Fix::Enable(s.unit)),
            });
        }
    }
    out.extend(checks.iter().filter(|c| c.problem).map(|c| Item::Problem {
        text: c.text.clone(),
        fix: None,
    }));
    out.extend(installed().map(|s| Item::Service(s.unit)));
    out.extend(
        checks
            .iter()
            .filter(|c| !c.problem)
            .map(|c| Item::Check(c.text.clone())),
    );
    out
}

/// How a unit's state reads on Status and Service.
pub fn state_word(active: &str) -> &str {
    match active {
        "active" => "running",
        "inactive" => "stopped",
        other => other,
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let items = app.status_items();
    let enter = match items.get(app.nav.row) {
        Some(Item::Service(unit)) => Some(format!("Open {}", unit.label())),
        Some(Item::Problem {
            fix: Some(Fix::Start(unit)),
            ..
        }) => Some(format!("Start {}", unit.label())),
        Some(Item::Problem {
            fix: Some(Fix::Enable(unit)),
            ..
        }) => Some(format!("Fix {}", unit.label())),
        _ => None,
    };
    let keys: Vec<(&str, &str)> = enter.iter().map(|l| ("Enter", l.as_str())).collect();
    let area = frame::draw(
        frame,
        &app.theme,
        head,
        Some("Status"),
        &app.bar(Bar::keys(&keys)),
    );
    let t = &app.theme;
    let mut rows = Vec::new();
    let heading = |rows: &mut Vec<Row>, text: &str, right: String| {
        rows.push(Row::Heading {
            text: text.into(),
            right,
        });
    };
    if items.iter().any(|i| matches!(i, Item::Problem { .. })) {
        heading(&mut rows, "Needs attention", String::new());
    }
    for item in &items {
        if let Item::Problem { text, fix } = item {
            let (mark, style) = if matches!(fix, Some(Fix::Start(_))) {
                ("■ ", t.red())
            } else {
                ("▲ ", t.yellow())
            };
            rows.push(Row::Entry {
                name: vec![Span::styled(mark, style), Span::raw(text.clone())],
                value: Vec::new(),
            });
        }
    }
    let installed: Vec<&ServiceStatus> = app.services.iter().filter(|s| s.installed).collect();
    let running = installed.iter().filter(|s| s.active == "active").count();
    heading(
        &mut rows,
        "Services",
        format!("{running} of {} running", installed.len()),
    );
    for s in installed {
        let dot = if s.active == "active" {
            Span::styled("● ", t.green())
        } else {
            Span::styled("■ ", t.red())
        };
        let ready = match s.ready {
            Some(true) => "ready",
            Some(false) => "not ready",
            None => "–",
        };
        let mut value = vec![Span::raw(format!(
            "{:<9} {:<9} ",
            state_word(&s.active),
            ready
        ))];
        if let Some(raw) = &s.since {
            value.push(Span::styled(format!("since {}", since(raw)), t.dim()));
        }
        rows.push(Row::Entry {
            name: vec![dot, Span::raw(s.unit.label().to_owned())],
            value,
        });
    }
    let ok: Vec<&String> = items
        .iter()
        .filter_map(|i| {
            if let Item::Check(c) = i {
                Some(c)
            } else {
                None
            }
        })
        .collect();
    if !ok.is_empty() {
        heading(&mut rows, "Checks", format!("{} ok", ok.len()));
    }
    for text in ok {
        rows.push(Row::Entry {
            name: vec![Span::styled("● ", t.green()), Span::raw(text.clone())],
            value: Vec::new(),
        });
    }
    let mut scroll = app.nav.scroll.get();
    let mut lines = list::lines(
        t,
        &rows,
        app.nav.row,
        &mut scroll,
        area.height.saturating_sub(1),
        18,
    );
    // The line under the list: the highlighted problem or check in full.
    if let Some(Item::Problem { text, .. } | Item::Check(text)) = items.get(app.nav.row) {
        lines.push(Line::styled(format!("    {}", cut(text, 72)), t.dim()));
    }
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

/// `text`, cut with "…" only when it is longer than `max` columns.
fn cut(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let kept: String = text.chars().take(max - 1).collect();
    format!("{kept}…")
}

/// systemd's `Sat 2026-10-10 12:56:13 CEST` as `12:56` when that day is
/// today, else `2026-10-10`; text that does not parse is returned as it is.
pub fn since(raw: &str) -> String {
    since_on(raw, chrono::Local::now().date_naive())
}

pub(super) fn since_on(raw: &str, today: chrono::NaiveDate) -> String {
    let mut parts = raw.split_whitespace();
    let parsed = parts
        .by_ref()
        .find_map(|p| chrono::NaiveDate::parse_from_str(p, "%Y-%m-%d").ok())
        .zip(
            parts
                .next()
                .and_then(|t| t.get(..5))
                .filter(|t| t.as_bytes()[2] == b':'),
        );
    match parsed {
        Some((day, time)) if day == today => time.to_owned(),
        Some((day, _)) => day.to_string(),
        None => raw.to_owned(),
    }
}

impl<H: Host> App<H> {
    pub(super) fn status_items(&self) -> Vec<Item> {
        items(&self.services, &self.database.health)
    }

    /// Home's one-line summary: a failed refresh first, then no services,
    /// then the problems.
    pub(super) fn status_line(&self) -> Line<'static> {
        let problems = self
            .status_items()
            .iter()
            .filter(|i| matches!(i, Item::Problem { .. }))
            .count();
        let installed = self.services.iter().filter(|s| s.installed).count();
        let (mark, style, text) = if let Some(error) = &self.message {
            ("✗ ", self.theme.red(), error.clone())
        } else if installed == 0 {
            (
                "▲ ",
                self.theme.yellow(),
                "No services installed · see Status".to_owned(),
            )
        } else if problems == 0 {
            (
                "● ",
                self.theme.green(),
                format!("All {installed} services running"),
            )
        } else {
            let things = if problems == 1 {
                "1 thing needs"
            } else {
                &format!("{problems} things need")
            };
            (
                "▲ ",
                self.theme.yellow(),
                format!("{things} attention · see Status"),
            )
        };
        Line::from(vec![
            Span::raw("    "),
            Span::styled(mark, style),
            if self.message.is_some() {
                Span::styled(text, style)
            } else {
                Span::raw(text)
            },
        ])
    }

    pub(super) fn status_key(&mut self, key: Key) {
        let items = self.status_items();
        if self.move_row(key, items.len()) || key != Key::Enter {
            return;
        }
        match items.get(self.nav.row) {
            Some(Item::Service(unit)) => {
                let unit = *unit;
                self.nav.go(Screen::Service(unit));
                self.selected = self
                    .services
                    .iter()
                    .position(|s| s.unit == unit)
                    .unwrap_or(0);
                self.load_logs();
            }
            Some(Item::Problem { fix: Some(fix), .. }) => self.ask_fix(*fix),
            _ => {}
        }
    }
}
