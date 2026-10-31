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

/// Home's entries; the appliance adds System and ends in Log out (spec §7).
pub fn items(appliance: bool) -> Vec<(&'static str, &'static str)> {
    let mut items = vec![
        ("Status", "health, services, logs"),
        ("Maintenance", "updates, repair, database, backup"),
    ];
    if appliance {
        items.push(("System", "restart, shut down"));
    }
    items.push((if appliance { "Log out" } else { "Quit" }, ""));
    items
}

fn rows(items: &[(&str, &str)]) -> Vec<Row> {
    items.iter().map(|(n, v)| Row::entry(n, v)).collect()
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let items = items(app.host.is_appliance());
    let enter = if app.nav.row == items.len() - 1 {
        items[app.nav.row].0
    } else {
        "Open"
    };
    let bar = app.bar(Bar::home(&[("Enter", enter)]));
    let area = frame::draw(frame, &app.theme, head, None, &bar);
    let mut lines = vec![app.status_line()];
    // The work's note beside the summary, else on a line of its own.
    if let Some(note) = app.work_note() {
        let note = Line::from(note);
        if lines[0].width() + 3 + note.width() <= usize::from(area.width) {
            lines[0].spans.push(Span::raw("   "));
            lines[0].spans.extend(note.spans);
        } else {
            lines.push(Line::from([vec![Span::raw("    ")], note.spans].concat()));
        }
    }
    let mut scroll = app.nav.scroll.get();
    let height = area
        .height
        .saturating_sub(u16::try_from(lines.len()).unwrap_or(u16::MAX));
    lines.extend(list::lines(
        &app.theme,
        &rows(&items),
        app.nav.row,
        &mut scroll,
        height,
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
        Screen::System => "System".into(),
        Screen::Network => "Network".into(),
        Screen::Time => "Time".into(),
        Screen::Ssh => "SSH".into(),
        Screen::LoginPassword => "Login password".into(),
        Screen::Status => "Status".into(),
        Screen::Service(unit) => format!("Service: {}", unit.label()),
        Screen::Log(unit) => format!("Log: {}", unit.label()),
        Screen::Help(_) | Screen::Install(_) => String::new(),
    }
}

/// What the keys do on the screen Help was opened from.
fn here(from: &Screen) -> &'static str {
    match from {
        Screen::Home | Screen::Maintenance => "Enter opens the highlighted entry.",
        Screen::Maint(page) => page.help(),
        Screen::System => super::system::HELP,
        Screen::Network => "Space chooses; Enter changes a value or applies it.",
        Screen::Time => "Enter changes a value or applies it.",
        Screen::LoginPassword => "Enter types a field, then Enter applies.",
        Screen::Ssh => "Space selects or deselects; Enter applies.",
        Screen::Status => "Enter opens a service, or does what a problem's line says.",
        Screen::Service(_) => "Enter does the highlighted action; Full log shows every line.",
        Screen::Log(_) => "⭡⭣ scroll the log.",
        Screen::Help(_) | Screen::Install(_) => "",
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
        let appliance = self.host.is_appliance();
        if self.move_row(&key, items(appliance).len()) {
            return;
        }
        if key == Key::Enter {
            match (self.nav.row, appliance) {
                (0, _) => self.open_status(),
                (1, _) => self.nav.go(Screen::Maintenance),
                (2, true) => self.open_system(),
                _ => self.quit_or_ask(),
            }
        }
    }
}
