//! Maintenance › Console sign-in (maint2b.py): a new one-time password for
//! the console's `admin`, shown once. The password lives in a
//! `Zeroizing<String>` that is taken out of the run's result as soon as
//! the run ends and dropped when the page is left; it is never journalled.

use platform_host::{Host, StepState};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};
use zeroize::Zeroizing;

use super::{Then, failure, info};
use crate::tui::{
    app::{App, Key, Question},
    run::{Call, Kind, Run, Work},
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};

/// The new password; its `Debug` is redacted so no derive can print it.
pub struct Shown(Zeroizing<String>);

impl std::fmt::Debug for Shown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Shown(..)")
    }
}

pub fn work() -> Work {
    Work::new(Kind::SignIn, vec![Call::AdminReset])
}

fn signin_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run.as_ref().filter(|r| r.work.kind == Kind::SignIn)
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let run = signin_run(app);
    let shown = app.maint.signin.as_ref();
    let bar = match run {
        Some(r) if r.running() => Bar::Busy {
            text: "Resetting the admin password…".into(),
            tick: app.tick_count,
        },
        Some(r) if r.ok() && shown.is_some() => Bar::only(&[("Enter", "Done")]),
        Some(r) if !r.ok() => Bar::act(&[("Enter", "Try again")]),
        _ => Bar::keys(&[("Enter", "Reset the admin password")]),
    };
    let area = frame::draw(frame, t, head, Some("Console sign-in"), &app.bar(bar));
    let mut lines = vec![
        Line::raw(""),
        Line::styled(
            "    For when nobody can sign in to the console any more.",
            t.dim(),
        ),
        Line::raw(""),
    ];
    match (run, shown) {
        (Some(r), Some(password)) if r.ok() => {
            lines.push(info("Sign in as", vec![Span::raw("admin")]));
            // Borrowed: no plain copy of the password is made per frame.
            lines.push(Line::from(vec![
                Span::raw(format!("    {:<26} ", "New password")),
                Span::styled(password.0.as_str(), t.bold()),
                Span::styled("  shown only now", t.dim()),
            ]));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "    You are asked to change it at the next sign-in.",
                t.dim(),
            ));
        }
        (Some(r), _) if !r.running() && !r.ok() => {
            let why = r.states[0].as_ref().map_or("", StepState::detail);
            // The helper's own words, without HostError's "failed: ".
            let why = why.strip_prefix("failed: ").unwrap_or(why);
            lines.extend(failure(
                t,
                &format!("✗ {why}"),
                "No new password was shown. Try again when that is fixed.",
            ));
        }
        _ => {
            let rows = [Row::entry(
                "Reset the admin password",
                "a new password, shown once",
            )];
            let mut scroll = app.nav.scroll.get();
            lines.extend(list::lines(t, &rows, 0, &mut scroll, 3, 26));
            app.nav.scroll.set(scroll);
        }
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_signin(&mut self) {
        self.nav.row = 0;
        // A password nobody has seen yet (the run ended while the page was
        // off screen) is shown now; a seen result is not news.
        if self.maint.signin.is_none() && signin_run(self).is_some_and(|r| !r.running()) {
            self.run = None;
        }
    }

    /// Leaving the page: the password is dropped (zeroized).
    pub(in crate::tui) fn signin_left(&mut self) {
        self.maint.signin = None;
    }

    pub(super) fn signin_key(&mut self, key: Key) {
        if key != Key::Enter {
            return;
        }
        match signin_run(self) {
            Some(r) if r.running() => {}
            Some(r) if r.ok() => {
                self.signin_left();
                self.run = None;
                self.back();
            }
            Some(r) => {
                let work = r.work.clone();
                self.begin(work, 0);
            }
            None => {
                self.question = Some((
                    Question::Maint {
                        text: "Reset the admin password?".into(),
                        detail: "old one stops".into(),
                        then: Then::SignIn,
                    },
                    true,
                ));
            }
        }
    }

    pub(super) fn signin_yes(&mut self) {
        self.begin(work(), 0);
    }

    /// A reset ended: the password moves out of the run into the page.
    pub(super) fn signin_ended(&mut self) {
        let Some(run) = self
            .run
            .as_mut()
            .filter(|r| r.work.kind == Kind::SignIn && !r.running())
        else {
            return;
        };
        if let Some(StepState::Done(text)) = run.states[0].as_mut() {
            self.maint.signin = Some(Shown(Zeroizing::new(std::mem::take(text))));
        }
    }
}
