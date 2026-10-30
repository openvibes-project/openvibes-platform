//! Maintenance › Console sign-in (maint2b.py): a new one-time password for
//! the console's `admin`, shown once. The password lives in a
//! `Zeroizing<String>` that is taken out of the run's result as soon as
//! the run ends and dropped when the page is left; it is never journalled.

use platform_host::{Database, Host, StepState};
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

fn sso_work() -> Work {
    Work::new(Kind::SsoOff, vec![Call::SsoOff])
}

fn sso_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run.as_ref().filter(|r| r.work.kind == Kind::SsoOff)
}

/// What the page says about single sign-on, and what the second row does.
fn sso_line(status: Option<&str>) -> (&'static str, &'static str) {
    match status {
        Some("on") => ("on", "people sign in through the identity provider"),
        Some("off") => ("off", "nothing to turn off"),
        Some("not set up") => ("not set up", "nothing to turn off"),
        _ => ("unknown", "cannot be read"),
    }
}

fn signin_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run.as_ref().filter(|r| r.work.kind == Kind::SignIn)
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let run = signin_run(app);
    let shown = app.maint.signin.as_ref();
    let sso = sso_run(app);
    let bar = match run {
        _ if sso.is_some_and(Run::running) => Bar::Busy {
            text: "Turning single sign-on off…".into(),
            tick: app.tick_count,
        },
        _ if sso.is_some_and(Run::ok) => Bar::only(&[("Enter", "Done")]),
        _ if sso.is_some() => Bar::act(&[("Enter", "Try again")]),
        None if app.nav.row == 1 && app.maint.sso.as_deref() == Some("on") => {
            Bar::keys(&[("Enter", "Turn single sign-on off")])
        }
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
        _ if sso.is_some() => {
            let r = sso.expect("checked");
            if r.running() {
                lines.push(Line::styled("    Turning single sign-on off…", t.dim()));
            } else if r.ok() {
                let said = r.states[0].as_ref().map_or("", StepState::detail);
                let words = match said {
                    "off" => "✓ Single sign-on is off. People sign in with their passwords.",
                    "already off" => "Single sign-on was already off.",
                    _ => "Single sign-on is not set up, so there is nothing to turn off.",
                };
                lines.push(Line::raw(format!("    {words}")));
            } else {
                let why = r.states[0].as_ref().map_or("", StepState::detail);
                let why = why.strip_prefix("failed: ").unwrap_or(why);
                lines.extend(failure(
                    t,
                    &format!("✗ {why}"),
                    "Single sign-on is as it was. Try again when that is fixed.",
                ));
            }
        }
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
            let (state, detail) = sso_line(app.maint.sso.as_deref());
            lines.insert(
                lines.len() - 1,
                Line::styled(format!("    Single sign-on: {state}"), t.dim()),
            );
            let rows = [
                Row::entry("Reset the admin password", "a new password, shown once"),
                Row::entry("Turn single sign-on off", detail),
            ];
            let mut scroll = app.nav.scroll.get();
            let room = area
                .height
                .saturating_sub(u16::try_from(lines.len()).unwrap_or(u16::MAX));
            lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, room, 26));
            app.nav.scroll.set(scroll);
        }
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_signin(&mut self) {
        self.nav.row = 0;
        self.sso_status();
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

    /// Reads whether single sign-on is on (no password; a quick database read).
    fn sso_status(&mut self) {
        self.maint.sso = self
            .host
            .database(Database::SsoStatus)
            .ok()
            .map(|text| text.trim().to_owned());
    }

    pub(super) fn signin_key(&mut self, key: Key) {
        if let Some((running, ok)) = sso_run(self).map(|r| (r.running(), r.ok())) {
            if key == Key::Enter && !running {
                if ok {
                    self.run = None;
                    self.sso_status();
                } else {
                    self.begin(sso_work(), 0);
                }
            }
            return;
        }
        if signin_run(self).is_none() && self.move_row(&key, 2) {
            return;
        }
        if key != Key::Enter {
            return;
        }
        if signin_run(self).is_none() && self.nav.row == 1 {
            if self.maint.sso.as_deref() == Some("on") {
                self.question = Some((
                    Question::Maint {
                        text: "Turn single sign-on off?".into(),
                        detail: "passwords only".into(),
                        then: Then::SsoOff,
                    },
                    true,
                ));
            }
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

    pub(super) fn sso_off_yes(&mut self) {
        self.begin(sso_work(), 0);
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
        // An empty Done shows nothing to sign in with: it is a failure.
        if matches!(&run.states[0], Some(StepState::Done(text)) if text.is_empty()) {
            run.states[0] = Some(StepState::Failed("the reset gave no password".into()));
        }
        if let Some(StepState::Done(text)) = run.states[0].as_mut() {
            self.maint.signin = Some(Shown(Zeroizing::new(std::mem::take(text))));
        }
    }
}
