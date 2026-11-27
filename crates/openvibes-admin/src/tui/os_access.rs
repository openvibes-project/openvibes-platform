//! Appliance settings › OS access, on the appliance only (#566, ruling
//! #554; osaccess.py, approved.md 60): the operating system's command
//! line at three levels. Read only asks (Yes first), User asks (No
//! first: danger), Root asks nothing but a typed `root` (bigger danger).
//! No password: the TUI already runs as root for the account that signed
//! in. The main loop hands the terminal to the shell (`Host::os_access`,
//! journalled there) and takes it back when it exits.

use chrono::{DateTime, Local};
use platform_host::{Host, shell::Access};
use ratatui::{Frame, text::Line, widgets::Paragraph};

use super::{
    app::{App, Key, Question},
    maint::Then,
    nav::Screen,
    status::wrap,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};

/// What is typed to open the root shell.
const WORD: &str = "root";

const HELP: [&str; 3] = [
    "Files, logs and services can be read; nothing can be written or started.",
    "Your account's own shell. What you change, OpenVIBES does not know about.",
    "Everything on this appliance can be changed, and nothing undoes it. Repair can put OpenVIBES' own files right again; nothing else.",
];

/// What Help says here.
pub const KEYS: &str = "Enter asks first; Root opens when root is typed.";

fn rows<H: Host>(app: &App<H>) -> Vec<Row> {
    let t = &app.theme;
    let user = platform_host::shell::operator();
    let level = |name: &str, value: String, style: ratatui::style::Style| Row::Entry {
        name: vec![ratatui::text::Span::styled(name.to_owned(), style)],
        value: vec![ratatui::text::Span::styled(value, style)],
    };
    vec![
        Row::entry("Read only", "look at everything, change nothing"),
        level("User", format!("danger: a shell as {user}"), t.yellow()),
        level("Root", "bigger danger: a shell as root".into(), t.red()),
    ]
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let row = app.nav.row.min(2);
    let bar = match &app.maint.os_typed {
        Some(text) => Bar::Typing {
            note: None,
            label: format!("Type {WORD} to open it"),
            shown: text.clone(),
            done: "Open".into(),
        },
        None => Bar::keys(&[("Enter", "Open")]),
    };
    let area = frame::draw(frame, t, head, Some("OS access"), &app.bar(bar));
    let mut scroll = app.nav.scroll.get();
    let mut lines = list::lines(t, &rows(app), row, &mut scroll, 7, 18);
    app.nav.scroll.set(scroll);
    lines.push(Line::raw(""));
    let style = if app.maint.os_typed.is_some() {
        t.red()
    } else {
        t.dim()
    };
    lines.extend(
        wrap(HELP[row], 76, 3)
            .into_iter()
            .map(|l| Line::styled(format!("    {l}"), style)),
    );
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_os_access(&mut self) {
        self.maint.os_typed = None;
        self.nav.go(Screen::OsAccess);
    }

    pub(super) fn os_access_key(&mut self, key: Key) {
        if let Some(text) = &mut self.maint.os_typed {
            match key {
                Key::Char(c) if text.len() < 16 && !c.is_control() => text.push(c),
                Key::Backspace => {
                    text.pop();
                }
                Key::ClearLine => text.clear(),
                Key::Esc => self.maint.os_typed = None,
                // Anything but the word does nothing.
                Key::Enter if text == WORD => {
                    self.maint.os_typed = None;
                    self.os_access = Some(Access::Root);
                }
                _ => {}
            }
            return;
        }
        if self.move_row(&key, 3) || key != Key::Enter {
            return;
        }
        let user = platform_host::shell::operator();
        let (text, detail, access, yes) = match self.nav.row {
            0 => (
                "Open a read-only shell?".into(),
                "logged".into(),
                Access::ReadOnly,
                true,
            ),
            1 => (
                format!("Open a shell as {user}?"),
                "danger".into(),
                Access::User,
                false,
            ),
            _ => {
                self.maint.os_typed = Some(String::new());
                return;
            }
        };
        self.question = Some((
            Question::Maint {
                text,
                detail,
                then: Then::OsAccess(access),
            },
            yes,
        ));
    }

    /// Yes to Read only or User: the main loop opens the shell next.
    pub(super) fn os_access_yes(&mut self, access: Access) {
        self.os_access = Some(access);
    }

    /// The level to open, once: the main loop restores the terminal first.
    pub fn take_os_access(&mut self) -> Option<Access> {
        self.os_access.take()
    }

    /// Runs the shell until it exits; one that cannot start says so here.
    pub fn run_os_access(&mut self, access: Access) {
        if let Err(error) = self.host.os_access(access) {
            let error = error.to_string();
            let why = error.strip_prefix("failed: ").unwrap_or(&error);
            self.outcome = Some((false, format!("The shell could not start: {why}")));
        }
    }
}

/// The two lines printed above the shell (osaccess.py #6, #8, #10).
pub fn header_for(access: Access, user: &str, now: DateTime<Local>) -> [String; 2] {
    let at = now.format("%H:%M");
    match access {
        Access::ReadOnly => [
            format!(
                "OS access, read only · type exit to go back to the menu. Logged as {user}, {at}."
            ),
            "Everything can be read; nothing can be written, started or stopped.".into(),
        ],
        Access::User => [
            format!("OS access as {user} · type exit to go back to the menu. Logged, {at}."),
            "Danger: what you change here, OpenVIBES does not know about.".into(),
        ],
        Access::Root => [
            format!(
                "OS access as root · type exit to go back to the menu. Logged as {user}, {at}."
            ),
            "Bigger danger: everything can be changed, and nothing undoes it.".into(),
        ],
    }
}

#[cfg(test)]
#[path = "os_access_tests.rs"]
mod tests;
