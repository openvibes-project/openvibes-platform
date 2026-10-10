//! Home, the interim Maintenance menu, and Help (spec §3, §2).

use platform_host::Host;
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    app::{App, Key, Tab},
    nav::Screen,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};

pub const HOME: [(&str, &str); 3] = [
    ("Status", "health, services, logs"),
    (
        "Maintenance",
        "setup, settings files, database (until reworked)",
    ),
    ("Quit", ""),
];
pub const MAINTENANCE: [(&str, &str); 3] = [
    ("Setup", "repair, update, components, ports, uninstall"),
    ("Settings files", "edit each service's configuration"),
    ("Database", "status, migrate, maintenance"),
];

fn rows(items: &[(&str, &str)]) -> Vec<Row> {
    items.iter().map(|(n, v)| Row::entry(n, v)).collect()
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let bar = app.bar(Bar::home(&[("Enter", "Open")]));
    let area = frame::draw(frame, &app.theme, head, None, &bar);
    let mut lines = vec![app.status_line()];
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(
        &app.theme,
        &rows(&HOME),
        app.nav.row,
        &mut scroll,
        area.height.saturating_sub(1),
        15,
    ));
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw_maintenance<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let bar = app.bar(Bar::keys(&[("Enter", "Open")]));
    let area = frame::draw(frame, &app.theme, head, Some("Maintenance"), &bar);
    let mut scroll = app.nav.scroll.get();
    let lines = list::lines(
        &app.theme,
        &rows(&MAINTENANCE),
        app.nav.row,
        &mut scroll,
        area.height,
        18,
    );
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw_help<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, from: &Screen) {
    let bar = Bar::Keys {
        keys: Vec::new(),
        nav: false,
        home: false,
    };
    let area = frame::draw(frame, &app.theme, head, Some("Keys"), &bar);
    let t = &app.theme;
    let key = |k: &str| Span::styled(format!(" {k} "), t.key());
    let pair = |lk: &str, ld: &str, rk: &str, rd: &str| {
        let pad = " ".repeat(8usize.saturating_sub(lk.chars().count() + 2));
        let mut spans = vec![
            Span::raw("    "),
            key(lk),
            Span::raw(format!("{pad}{ld:<24}   ")),
        ];
        if !rk.is_empty() {
            let pad = " ".repeat(6usize.saturating_sub(rk.chars().count() + 2));
            spans.push(key(rk));
            spans.push(Span::raw(format!("{pad}{rd}")));
        }
        Line::from(spans)
    };
    let lines = vec![
        Line::raw(""),
        pair(t.up_down(), "move · lists scroll", "Esc", "back, or cancel"),
        Line::raw(""),
        pair("Enter", "open, change, confirm", "?", "this help"),
        Line::raw(""),
        pair("Space", "select or deselect", "q", "quit, from Home"),
        Line::raw(""),
        pair(t.left_right(), "Yes or No in a question", "", ""),
        Line::raw(""),
        Line::styled(format!("    Here: {}", here(from)), t.dim()),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

/// What the keys do on the screen Help was opened from.
fn here(from: &Screen) -> &'static str {
    match from {
        Screen::Home | Screen::Maintenance => "Enter opens the highlighted entry.",
        Screen::Status => "Enter opens a service, or does what a problem's line says.",
        Screen::Service(_) => "Enter does the highlighted action; Full log shows every line.",
        Screen::Log(_) => "⭡⭣ scroll the log.",
        Screen::Help(_) | Screen::Legacy => "",
    }
}

impl<H: Host> App<H> {
    /// ⭡⭣ (j/k) move the highlight; true when `key` was one of them.
    pub(super) fn move_row(&mut self, key: Key, count: usize) -> bool {
        match key {
            Key::Down | Key::Char('j') if self.nav.row + 1 < count => self.nav.row += 1,
            Key::Up | Key::Char('k') if self.nav.row > 0 => self.nav.row -= 1,
            Key::Down | Key::Up | Key::Char('j' | 'k') => {}
            _ => return false,
        }
        true
    }

    pub(super) fn home_key(&mut self, key: Key) {
        if self.move_row(key, HOME.len()) {
            return;
        }
        if key == Key::Enter {
            match self.nav.row {
                0 => self.open(Tab::Health),
                1 => self.nav.go(Screen::Maintenance),
                _ => self.quit_or_ask(),
            }
        }
    }

    pub(super) fn maintenance_key(&mut self, key: Key) {
        if self.move_row(key, MAINTENANCE.len()) {
            return;
        }
        if key == Key::Enter {
            self.open([Tab::Setup, Tab::Configuration, Tab::Database][self.nav.row]);
        }
    }
}
