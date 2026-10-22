//! Quick install (quick.py): only what OpenVIBES cannot know. The host
//! name, other names and root key file are edited in place; everything
//! else is the defaults (OpenVIBES's own CA, the default ports, no
//! assistant).

use std::path::Path;

use platform_host::Host;
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Ca, Install, Stage};
use crate::tui::{
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

const NAMES: [&str; 3] = ["Host name", "Other names", "Root key file"];
const AGENT: usize = 3;
const INSTALL: usize = 4;
const HELP: [&str; 5] = [
    "The name agents and your browser use to reach this host.",
    "Other names or addresses agents may use, comma-separated.",
    "The CA's root key: written once here, move it offline.",
    "Untick only if this server must not run an agent.",
    "Starts the install; it asks for your password once.",
];

fn exists(path: &str) -> bool {
    Path::new(path).exists()
}

impl Install {
    fn field(&mut self, row: usize) -> &mut String {
        match row {
            0 => &mut self.hostname,
            1 => &mut self.sans,
            _ => &mut self.root_key_out,
        }
    }
}

fn row<H: Host>(app: &App<H>, i: usize) -> Row {
    let t = &app.theme;
    let install = &app.install;
    let typing = install.editing.is_some() && app.nav.row == i;
    let value = |text: &str, empty: &str| {
        let shown = if text.is_empty() && !typing {
            empty
        } else {
            text
        };
        format!("{shown}{}", if typing { "█" } else { "" })
    };
    let (name, shown) = match i {
        0 => (NAMES[0], value(&install.hostname, "")),
        1 => (NAMES[1], value(&install.sans, "none")),
        2 => (NAMES[2], value(&install.root_key_out, "")),
        AGENT => (" Agent on this host", "watch this host too".to_owned()),
        _ => ("Install", "everything else uses the defaults".to_owned()),
    };
    if i == AGENT {
        let mark = if install.agent {
            Span::styled("[x]", t.green())
        } else {
            Span::raw("[ ]")
        };
        return Row::Entry {
            name: vec![mark, Span::raw(name)],
            value: vec![Span::styled(shown, t.dim())],
        };
    }
    Row::entry(name, &shown)
}

pub(super) fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let install = &app.install;
    let bar = match (install.editing.is_some(), app.nav.row) {
        (true, i) => Bar::edit(
            NAMES[i.min(2)],
            if i == 2 { "type a path" } else { "type a name" },
            &[("Enter", "Done")],
        ),
        (_, AGENT) => Bar::keys(&[("Space", "Select/deselect"), ("Enter", "Confirm")]),
        (_, INSTALL) => Bar::keys(&[("Enter", "Install")]),
        _ => Bar::keys(&[("Enter", "Change")]),
    };
    let area = frame::draw(
        frame,
        t,
        head,
        Some("Quick install: only what OpenVIBES cannot know"),
        &app.bar(bar),
    );
    let rows: Vec<Row> = (0..=INSTALL).map(|i| row(app, i)).collect();
    // A flagged field is said under the list, before any help.
    let (text, red) = match install.problem(exists) {
        Some((at, why)) => (format!("✗ {}: {why}", NAMES[at]), true),
        None => match (&install.port_note, app.nav.row) {
            (Some(note), INSTALL) => (note.clone(), false),
            _ => (HELP[app.nav.row.min(INSTALL)].to_owned(), false),
        },
    };
    let help = wrap(&text, 72, 2);
    // Five rows fit above one help line; a second line scrolls the list.
    let room = area.height.saturating_sub(help.len() as u16);
    let mut scroll = app.nav.scroll.get();
    let mut lines = list::lines(t, &rows, app.nav.row, &mut scroll, room, 22);
    app.nav.scroll.set(scroll);
    let style = if red { t.red() } else { t.dim() };
    lines.extend(
        help.into_iter()
            .map(|l| Line::styled(format!("    {l}"), style)),
    );
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn quick_key(&mut self, key: Key) {
        let at = self.nav.row;
        if let Some(was) = self.install.editing.clone() {
            let lower = at < 2;
            let text = self.install.field(at);
            match key {
                Key::Char(c) if !c.is_control() && text.len() < 253 => {
                    text.push(if lower { c.to_ascii_lowercase() } else { c });
                }
                Key::Backspace => {
                    text.pop();
                }
                Key::ClearLine => text.clear(),
                Key::Enter => self.install.editing = None,
                Key::Esc => {
                    *text = was;
                    self.install.editing = None;
                }
                _ => {}
            }
            return;
        }
        if self.move_row(key, INSTALL + 1) {
            return;
        }
        match (key, at) {
            (Key::Esc, _) => {
                self.nav.row = 0;
                self.nav.screen = Screen::Install(Stage::Welcome);
            }
            (Key::Enter, 0..=2) => self.install.editing = Some(self.install.field(at).clone()),
            (Key::Char(' '), AGENT) => self.install.agent = !self.install.agent,
            (Key::Enter, AGENT) => self.nav.row = INSTALL,
            // A flagged field is said under the list: nothing starts.
            (Key::Enter, INSTALL) if self.install.problem(exists).is_none() => {
                self.install.ca = Ca::OpenVibes;
                self.install.assistant = false;
                self.start_install();
            }
            _ => {}
        }
    }
}
