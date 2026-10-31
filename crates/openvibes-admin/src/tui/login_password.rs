//! System › Login password, on the appliance (spec §7): changes the
//! password of the account that signed in to this console. The new password
//! is typed twice, masked, and goes to the helper on standard input only.

use platform_host::Host;
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};
use zeroize::Zeroizing;

use super::{
    app::{App, Key, Question},
    kind::Kind,
    maint::Then,
    network::draw_run,
    password::{PasswordPrompt, Typed},
    run::{Bundle, Call, Run, Work},
    status::wrap,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};
use crate::setup::login::check;

/// A page row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum At {
    New,
    Again,
    Apply,
}

/// The page's state. Debug shows nothing typed.
#[derive(Default)]
pub struct LoginPage {
    new: Zeroizing<String>,
    again: Zeroizing<String>,
    /// The field being typed into.
    typing: Option<(At, PasswordPrompt)>,
    /// Said under the list.
    pub said: Option<String>,
}

impl std::fmt::Debug for LoginPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginPage")
    }
}

impl LoginPage {
    fn rows(&self) -> Vec<At> {
        let mut rows = vec![At::New, At::Again];
        if !self.new.is_empty() && !self.again.is_empty() {
            rows.push(At::Apply);
        }
        rows
    }

    /// Why Apply cannot go ahead, in the words the page shows.
    fn problem(&self) -> Option<String> {
        check(&self.new).err().or_else(|| {
            (self.new != self.again).then(|| "The two passwords are not the same.".to_owned())
        })
    }

    /// Rows shown (tests).
    #[cfg(test)]
    pub fn row_count(&self) -> usize {
        self.rows().len()
    }

    /// Typing a field.
    pub fn typing(&self) -> bool {
        self.typing.is_some()
    }
}

fn login_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::LoginPassword))
}

fn row<H: Host>(app: &App<H>, page: &LoginPage, at: At) -> Row {
    let t = &app.theme;
    let field = |name: &str, text: &str| {
        let live = page.typing.as_ref().filter(|(field, _)| *field == at);
        let value = match live {
            Some((_, prompt)) => format!("{}▏", prompt.masked()),
            None => "*".repeat(text.chars().count()),
        };
        Row::Entry {
            name: vec![Span::raw(name.to_owned())],
            value: vec![Span::styled(value, t.dim())],
        }
    };
    match at {
        At::New => field("New password", &page.new),
        At::Again => field("Repeat it", &page.again),
        At::Apply => Row::Entry {
            name: vec![Span::raw("Apply")],
            value: vec![Span::styled("changes the password".to_owned(), t.dim())],
        },
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let title = "Login password";
    if let Some(run) = login_run(app) {
        return draw_run(frame, head, app, run, title, "Try again runs it once more.");
    }
    let t = &app.theme;
    let page = &app.maint.login;
    let rows = page.rows();
    let at = rows.get(app.nav.row).copied();
    let bar = if page.typing() {
        Bar::keys(&[("Enter", "Done"), ("Esc", "Cancel")])
    } else {
        Bar::keys(&[("Enter", "Type it / Apply")])
    };
    let area = frame::draw(frame, t, head, Some(title), &app.bar(bar));
    let mut lines = Vec::new();
    let (text, style) = match (&page.said, at) {
        (Some(said), _) => (said.as_str(), t.yellow()),
        (None, Some(At::Apply)) => ("Changes the password you signed in with.", t.dim()),
        _ => (
            "At least 10 characters. Type it twice; nothing is shown.",
            t.dim(),
        ),
    };
    lines.extend(
        wrap(text, 72, 2)
            .into_iter()
            .map(|l| Line::styled(format!("    {l}"), style)),
    );
    lines.push(Line::raw(""));
    let list_rows: Vec<Row> = rows.iter().map(|r| row(app, page, *r)).collect();
    let height = area
        .height
        .saturating_sub(u16::try_from(lines.len()).unwrap_or(u16::MAX));
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(
        t,
        &list_rows,
        app.nav.row,
        &mut scroll,
        height,
        30,
    ));
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Opens the page with empty fields.
    pub(super) fn open_login_password(&mut self) {
        self.nav.row = 0;
        if login_run(self).is_some_and(|r| !r.running()) {
            self.run = None;
        }
        self.maint.login = LoginPage::default();
    }

    pub(super) fn login_password_key(&mut self, key: Key) {
        if let Some(run) = login_run(self) {
            if run.running() || key != Key::Enter {
                return;
            }
            if run.ok() {
                self.open_login_password();
            } else if let Some(at) = run.stopped_at() {
                let work = run.work.clone();
                self.begin(work, at);
            }
            return;
        }
        if let Some((field, prompt)) = &mut self.maint.login.typing {
            let field = *field;
            match prompt.key(key) {
                Typed::Pending => {}
                Typed::Cancelled => self.maint.login.typing = None,
                Typed::Entered(secret) => {
                    let text = Zeroizing::new(secret.expose().to_owned());
                    let page = &mut self.maint.login;
                    page.typing = None;
                    page.said = None;
                    match field {
                        At::New => page.new = text,
                        _ => page.again = text,
                    }
                    let last = page.rows().len().saturating_sub(1);
                    self.nav.row = (self.nav.row + 1).min(last);
                }
            }
            return;
        }
        let count = self.maint.login.rows().len();
        if self.move_row(&key, count) || key != Key::Enter {
            return;
        }
        match self.maint.login.rows().get(self.nav.row).copied() {
            Some(At::Apply) => self.ask_login_password(),
            Some(field) => self.maint.login.typing = Some((field, PasswordPrompt::default())),
            None => {}
        }
    }

    fn ask_login_password(&mut self) {
        if let Some(why) = super::maint::busy(self) {
            self.outcome = Some((false, why));
            return;
        }
        if let Some(problem) = self.maint.login.problem() {
            self.maint.login.said = Some(problem);
            return;
        }
        self.question = Some((
            Question::Maint {
                text: "Change your login password?".into(),
                detail: "the new password applies from the next sign-in".into(),
                then: Then::LoginPassword,
            },
            true,
        ));
    }

    pub(super) fn login_password_yes(&mut self) {
        let bundle = Bundle(Zeroizing::new(self.maint.login.new.to_string()));
        self.begin(
            Work::new(Kind::LoginPassword, vec![Call::LoginPassword(bundle)]),
            0,
        );
    }
}
