//! System, on the appliance only (spec §7; system.py, approved.md 43):
//! what a sealed appliance needs without a shell. This page holds the
//! power entries, Restart and Shut down; the network, time, password and
//! SSH entries arrive with their own pages. Both ask first, starting on
//! No, and a running one stays on the screen: the session ends with it.

use platform_host::{Host, StepState};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    app::{App, Key, Question},
    kind::OsAction,
    maint::{Then, busy, failure},
    nav::Screen,
    run::{Call, Kind, Run, Work},
    ui::{
        bar::{Bar, SPINNER},
        frame,
        list::{self, Row},
        logo::Header,
    },
};

/// The page's entries: (name, what it does).
const ENTRIES: [(&str, &str); 2] = [("Restart", ""), ("Shut down", "")];

fn power_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run.as_ref().filter(|r| {
        matches!(
            r.work.kind,
            Kind::Os(OsAction::Restart | OsAction::PowerOff)
        )
    })
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    if let Some(run) = power_run(app) {
        let mut lines = vec![Line::raw("")];
        let bar = if run.running() {
            let spin = SPINNER[app.tick_count % SPINNER.len()];
            lines.push(Line::from(vec![
                Span::styled(format!("    {spin} "), t.teal()),
                Span::raw(format!("{}…", run.work.kind.doing())),
            ]));
            lines.push(Line::styled("    The session ends now.", t.dim()));
            Bar::Busy {
                text: run.work.kind.doing(),
                tick: app.tick_count,
            }
        } else if run.ok() {
            lines.push(Line::styled(
                format!("    ✓ {}{}", run.work.kind.done(), run.took()),
                t.green(),
            ));
            Bar::act(&[])
        } else {
            let at = run.stopped_at().unwrap_or(0);
            let why = run.states[at].as_ref().map_or("", StepState::detail);
            lines.extend(failure(t, why, "Try again runs it once more."));
            Bar::act(&[("Enter", "Try again")])
        };
        let area = frame::draw(frame, t, head, Some("System"), &app.bar(bar));
        frame.render_widget(Paragraph::new(lines), area);
        return;
    }
    let bar = app.bar(Bar::keys(&[("Enter", ENTRIES[app.nav.row].0)]));
    let area = frame::draw(frame, t, head, Some("System"), &bar);
    let rows: Vec<Row> = ENTRIES.iter().map(|(n, v)| Row::entry(n, v)).collect();
    let mut scroll = app.nav.scroll.get();
    let lines = list::lines(t, &rows, app.nav.row, &mut scroll, area.height, 18);
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Opens the page; a finished power run is not news the next time.
    pub(super) fn open_system(&mut self) {
        if power_run(self).is_some_and(|r| !r.running()) {
            self.run = None;
        }
        self.nav.go(Screen::System);
    }

    pub(super) fn system_key(&mut self, key: Key) {
        if let Some((running, ok, work, at)) =
            power_run(self).map(|r| (r.running(), r.ok(), r.work.clone(), r.stopped_at()))
        {
            if key == Key::Enter && !running && !ok {
                self.begin(work, at.unwrap_or(0));
            }
            return;
        }
        if self.move_row(&key, ENTRIES.len()) || key != Key::Enter {
            return;
        }
        if let Some(why) = busy(self) {
            self.outcome = Some((false, why));
            return;
        }
        let (text, detail, then) = if self.nav.row == 0 {
            ("Restart the appliance?", "about 1 minute", Then::OsRestart)
        } else {
            (
                "Shut the appliance down?",
                "it stays off until someone starts it",
                Then::OsPowerOff,
            )
        };
        self.question = Some((
            Question::Maint {
                text: text.into(),
                detail: detail.into(),
                then,
            },
            false,
        ));
    }

    pub(super) fn os_power_off_yes(&mut self) {
        self.begin(
            Work::new(Kind::Os(OsAction::PowerOff), vec![Call::OsPowerOff]),
            0,
        );
    }
}

/// What Help says here.
pub const HELP: &str = "Enter asks first, then restarts or shuts down the appliance.";
