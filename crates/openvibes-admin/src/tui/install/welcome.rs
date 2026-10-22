//! Welcome (install.py `welcome`): what a host that does not run OpenVIBES
//! yet opens on.

use platform_host::Host;
use ratatui::{Frame, text::Line, widgets::Paragraph};

use super::Stage;
use crate::tui::{
    app::{App, Key},
    nav::Screen,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};

const ENTRIES: [(&str, &str); 3] = [
    ("Choose what to install", "components, names, ports"),
    ("Quick install", "everything, with default names and ports"),
    ("Quit", ""),
];

pub(super) fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let enter = if app.nav.row == ENTRIES.len() - 1 {
        "Quit"
    } else {
        "Open"
    };
    let bar = app.bar(Bar::home(&[("Enter", enter)]));
    let area = frame::draw(frame, &app.theme, head, None, &bar);
    let rows: Vec<Row> = ENTRIES.iter().map(|(n, v)| Row::entry(n, v)).collect();
    // The list's own top line is the empty one under the sentence.
    let mut lines = vec![Line::raw("    This host does not run OpenVIBES yet.")];
    let mut scroll = app.nav.scroll.get();
    let room = area.height.saturating_sub(1);
    lines.extend(list::lines(
        &app.theme,
        &rows,
        app.nav.row,
        &mut scroll,
        room,
        24,
    ));
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn welcome_key(&mut self, key: Key) {
        if self.move_row(&key, ENTRIES.len()) {
            return;
        }
        match (key, self.nav.row) {
            (Key::Char('q'), _) | (Key::Enter, 2) => self.quit = true,
            (Key::Enter, 0) => self.nav.screen = Screen::Install(Stage::Step(0)),
            (Key::Enter, 1) => {
                self.nav.row = 0;
                self.nav.screen = Screen::Install(Stage::Quick);
            }
            _ => {}
        }
    }
}
