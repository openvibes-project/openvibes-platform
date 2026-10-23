//! Home and Help (spec §3, §2).

use platform_host::Host;
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    app::{App, Key},
    nav::Screen,
    status::wrap,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};

pub const HOME: [(&str, &str); 3] = [
    ("Status", "health, services, logs"),
    ("Maintenance", "updates, repair, database, backup"),
    ("Quit", ""),
];

fn rows(items: &[(&str, &str)]) -> Vec<Row> {
    items.iter().map(|(n, v)| Row::entry(n, v)).collect()
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let enter = if app.nav.row == HOME.len() - 1 {
        "Quit"
    } else {
        "Open"
    };
    let bar = app.bar(Bar::home(&[("Enter", enter)]));
    let area = frame::draw(frame, &app.theme, head, None, &bar);
    let mut status = app.status_line();
    if let Some(note) = app.work_note() {
        status.spans.push(Span::raw("   "));
        status.spans.extend(note);
    }
    let mut lines = vec![status];
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

pub fn draw_help<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, from: &Screen) {
    let bar = Bar::Close;
    let area = frame::draw(frame, &app.theme, head, Some("Keys"), &bar);
    let t = &app.theme;
    let key = |k: &str| Span::styled(format!(" {k} "), t.key());
    let pair = |lk: &str, ld: &str, rk: &str, rd: &str| {
        let pad = " ".repeat(10usize.saturating_sub(lk.chars().count() + 2));
        let mut spans = vec![
            Span::raw("    "),
            key(lk),
            Span::raw(format!("{pad}{ld:<24}   ")),
        ];
        if !rk.is_empty() {
            let pad = " ".repeat(8usize.saturating_sub(rk.chars().count() + 2));
            spans.push(key(rk));
            spans.push(Span::raw(format!("{pad}{rd}")));
        }
        Line::from(spans)
    };
    let mut lines = vec![
        Line::raw(""),
        pair(t.up_down(), "move · lists scroll", "Esc", "back, or cancel"),
        Line::raw(""),
        pair("Enter", "open, change, confirm", "?", "this help"),
        Line::raw(""),
        pair("Space", "select or deselect", "q", "quit, from Home"),
        Line::raw(""),
        pair(t.left_right(), "Yes or No in a question", "", ""),
        Line::raw(""),
    ];
    // Wrapped, not cut at the frame's edge.
    let here = format!("Here ({}): {}", name(from), here(from));
    lines.extend(
        wrap(&here, 72, 3)
            .into_iter()
            .map(|l| Line::styled(format!("    {l}"), t.dim())),
    );
    frame.render_widget(Paragraph::new(lines), area);
}

/// The screen's name, as its title or location line says it.
fn name(screen: &Screen) -> String {
    match screen {
        Screen::Home => "Home".into(),
        Screen::Maintenance => "Maintenance".into(),
        Screen::Maint(page) => page.title().into(),
        Screen::Status => "Status".into(),
        Screen::Service(unit) => format!("Service: {}", unit.label()),
        Screen::Log(unit) => format!("Log: {}", unit.label()),
        Screen::Help(_) | Screen::Legacy | Screen::Install(_) => String::new(),
    }
}

/// What the keys do on the screen Help was opened from.
fn here(from: &Screen) -> &'static str {
    match from {
        Screen::Home | Screen::Maintenance => "Enter opens the highlighted entry.",
        Screen::Maint(page) => page.help(),
        Screen::Status => "Enter opens a service, or does what a problem's line says.",
        Screen::Service(_) => "Enter does the highlighted action; Full log shows every line.",
        Screen::Log(_) => "⭡⭣ scroll the log.",
        Screen::Help(_) | Screen::Legacy | Screen::Install(_) => "",
    }
}

impl<H: Host> App<H> {
    /// ⭡⭣ (j/k) move the highlight; true when `key` was one of them.
    pub(super) fn move_row(&mut self, key: &Key, count: usize) -> bool {
        match key {
            Key::Down | Key::Char('j') if self.nav.row + 1 < count => self.nav.row += 1,
            Key::Up | Key::Char('k') if self.nav.row > 0 => self.nav.row -= 1,
            Key::Down | Key::Up | Key::Char('j' | 'k') => {}
            _ => return false,
        }
        true
    }

    pub(super) fn home_key(&mut self, key: Key) {
        if self.move_row(&key, HOME.len()) {
            return;
        }
        if key == Key::Enter {
            match self.nav.row {
                0 => self.open_status(),
                1 => self.nav.go(Screen::Maintenance),
                _ => self.quit_or_ask(),
            }
        }
    }
}
