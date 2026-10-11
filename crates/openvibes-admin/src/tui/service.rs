//! Service: `<name>` (spec §4): which service, its state, its actions as
//! entries (the bar names what Enter does), and its latest log lines;
//! Full log shows every line.

use platform_host::{Host, ServiceAction, Unit};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    app::{App, Key, Question},
    nav::Screen,
    services_text::readable,
    status::state_word,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};

/// What an action means for this unit (the entry description).
pub fn detail(unit: Unit, action: ServiceAction) -> &'static str {
    match (unit, action) {
        (Unit::Ingest, ServiceAction::Restart) => "agents reconnect within a minute",
        (Unit::Ingest, ServiceAction::Stop) => "agents keep their findings until it runs",
        (_, ServiceAction::Restart) => "about a minute",
        (_, ServiceAction::Stop) => "until you start it",
        (_, ServiceAction::Start) => "starts it now",
    }
}

/// The short sentence in the question, which must fit the bar at 80 columns.
pub fn question_detail(unit: Unit, action: ServiceAction) -> &'static str {
    match (unit, action) {
        (Unit::Ingest, ServiceAction::Restart) => "agents reconnect",
        (Unit::Ingest, ServiceAction::Stop) => "agents hold their findings",
        (_, ServiceAction::Restart) => "back in a minute",
        _ => detail(unit, action),
    }
}

#[derive(Clone, Copy)]
enum Action {
    Do(ServiceAction),
    FullLog,
}

fn actions<H: Host>(app: &App<H>, unit: Unit) -> Vec<Action> {
    let active = app
        .services
        .iter()
        .any(|s| s.unit == unit && s.active == "active");
    let mut out = if active {
        vec![
            Action::Do(ServiceAction::Restart),
            Action::Do(ServiceAction::Stop),
        ]
    } else {
        vec![Action::Do(ServiceAction::Start)]
    };
    out.push(Action::FullLog);
    out
}

fn label(unit: Unit, action: Action) -> (&'static str, &'static str) {
    match action {
        Action::Do(ServiceAction::Restart) => ("Restart", detail(unit, ServiceAction::Restart)),
        Action::Do(ServiceAction::Stop) => ("Stop", detail(unit, ServiceAction::Stop)),
        Action::Do(ServiceAction::Start) => ("Start", detail(unit, ServiceAction::Start)),
        Action::FullLog => ("Full log", "every line, newest at the bottom"),
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, unit: Unit) {
    let acts = actions(app, unit);
    let enter = acts.get(app.nav.row).map(|a| match a {
        Action::FullLog => "Full log".to_owned(),
        Action::Do(_) => format!("{} {}", label(unit, *a).0, unit.label()),
    });
    let keys: Vec<(&str, &str)> = enter.iter().map(|e| ("Enter", e.as_str())).collect();
    let area = frame::draw(
        frame,
        &app.theme,
        head,
        Some(&format!("Service: {}", unit.label())),
        &app.bar(Bar::keys(&keys)),
    );
    let t = &app.theme;
    let status = app.services.iter().find(|s| s.unit == unit);
    let up = status.is_some_and(|s| s.active == "active");
    let state = status.map_or("unknown".to_owned(), |s| {
        let ready = match s.ready {
            Some(true) => " · ready",
            Some(false) => " · not ready",
            None => "",
        };
        let since = s
            .since
            .as_ref()
            .map(|x| format!(" · since {}", super::status::since(x)));
        let active = state_word(&s.active);
        format!("{active}{ready}{}", since.unwrap_or_default())
    });
    let dot = if up {
        Span::styled("● ", t.green())
    } else {
        Span::styled("■ ", t.red())
    };
    let mut lines = vec![
        Line::raw(""),
        Line::from(vec![Span::raw("    "), dot, Span::raw(state)]),
    ];
    let rows: Vec<Row> = acts
        .iter()
        .map(|a| {
            let (name, value) = label(unit, *a);
            Row::entry(name, value)
        })
        .collect();
    let mut scroll = app.nav.scroll.get();
    let height = u16::try_from(rows.len() * 2 + 1).unwrap_or(7);
    lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, height, 18));
    app.nav.scroll.set(scroll);
    lines.push(Line::styled("    Recent log", t.bold()));
    let room = usize::from(area.height).saturating_sub(lines.len());
    let tail = app.logs.len().saturating_sub(room);
    lines.extend(
        app.logs[tail..]
            .iter()
            .map(|l| Line::raw(format!("    {}", readable(l)))),
    );
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw_log<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, unit: Unit) {
    let area = frame::draw(
        frame,
        &app.theme,
        head,
        Some(&format!("Log: {}", unit.label())),
        &app.bar(Bar::keys(&[])),
    );
    let room = usize::from(area.height).saturating_sub(2);
    app.log_room.set(room);
    // However far Up was pressed, the window never goes above line 0.
    let row = app.nav.row.min(app.logs.len().saturating_sub(room));
    let end = app.logs.len().saturating_sub(row);
    let start = end.saturating_sub(room);
    let t = &app.theme;
    let mut lines = vec![if start > 0 {
        Line::styled(format!("    {} {start} more", t.up()), t.dim())
    } else {
        Line::raw("")
    }];
    lines.extend(
        app.logs[start..end]
            .iter()
            .map(|l| Line::raw(format!("    {}", readable(l)))),
    );
    if row > 0 {
        lines.push(Line::styled(
            format!("    {} {row} more", t.down()),
            t.dim(),
        ));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn service_key(&mut self, unit: Unit, key: Key) {
        let acts = actions(self, unit);
        // Work is running: the bar shows it; Enter starts nothing else.
        if self.pending.is_some() && key == Key::Enter {
            return;
        }
        if self.move_row(key, acts.len()) || key != Key::Enter {
            return;
        }
        match acts.get(self.nav.row) {
            Some(Action::Do(action)) => {
                self.question = Some((Question::Service(unit, *action), true));
            }
            Some(Action::FullLog) => {
                self.logs = self
                    .host
                    .logs(unit, 500)
                    .unwrap_or_else(|e| vec![e.to_string()]);
                self.nav.go(Screen::Log(unit));
            }
            None => {}
        }
    }

    /// In the full log, Up goes back in time (row counts lines from the
    /// end), until the first line is the window's top.
    pub(super) fn log_key(&mut self, key: Key) {
        let top = self.logs.len().saturating_sub(self.log_room.get());
        match key {
            Key::Up | Key::Char('k') if self.nav.row < top => self.nav.row += 1,
            Key::Down | Key::Char('j') if self.nav.row > 0 => self.nav.row -= 1,
            _ => {}
        }
    }
}
