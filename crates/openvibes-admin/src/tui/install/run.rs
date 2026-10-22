//! Installing and Finished (install.py): the rows of the install on the
//! worker; a stop offers Try again, Esc leaves.

use platform_host::{Host, StepState};
use ratatui::{Frame, text::Line, widgets::Paragraph};

use super::{Stage, finished};
use crate::tui::{
    app::{App, Key},
    maint::failure,
    nav::{Nav, Screen},
    run::{Run, is_model, label_states},
    ui::{bar::Bar, frame, logo::Header, steps},
};

impl<H: Host> App<H> {
    /// Review's Install: the password, then the work on the worker.
    pub(crate) fn start_install(&mut self) {
        // Esc after a failure goes back here: Quick install or Review.
        self.install.origin = match self.nav.screen {
            Screen::Install(Stage::Quick) => Stage::Quick,
            _ => Stage::Step(4),
        };
        self.nav.screen = Screen::Install(Stage::Running);
        self.run = None;
        let work = self.install.work();
        self.begin(work, 0);
    }

    /// A run ended on the Installing screen: a good one shows Finished.
    pub(in crate::tui) fn install_ended(&mut self) {
        self.ca_ended();
        if self.nav.screen == Screen::Install(Stage::Running)
            && self.run.as_ref().is_some_and(Run::ok)
        {
            self.nav.screen = Screen::Install(Stage::Finished);
        }
    }

    pub(in crate::tui) fn install_key(&mut self, stage: Stage, key: Key) {
        let stopped = self.run.as_ref().is_none_or(|r| !r.running());
        match (stage, key) {
            (Stage::Welcome, key) => self.welcome_key(key),
            (Stage::Quick, key) => self.quick_key(key),
            (Stage::Step(at), key) => self.step_key(at, key),
            (Stage::Request, key) => self.request_key(key),
            (Stage::Add(which), key) => self.add_key(which, key),
            (Stage::Finished, Key::Enter) => {
                self.run = None;
                self.nav = Nav::new(Screen::Home);
            }
            (Stage::Running, Key::Enter) if stopped => {
                if let Some(run) = &self.run
                    && let Some(at) = run.stopped_at()
                {
                    let work = run.work.clone();
                    self.begin(work, at);
                }
            }
            // Back where the install began while there is no CA (Quick
            // install or Review); Home once there is.
            (Stage::Running, Key::Esc) if stopped => {
                self.run = None;
                if self.ca_exists() {
                    self.nav = Nav::new(Screen::Home);
                } else {
                    self.nav.row = 0;
                    self.nav.screen = Screen::Install(self.install.origin);
                    if self.install.origin == Stage::Step(4) {
                        self.nav.row = 4;
                    }
                }
            }
            _ => {}
        }
    }
}

pub(in crate::tui) fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, stage: Stage) {
    match (stage, &app.run) {
        (Stage::Finished, Some(run)) => finished::draw(frame, head, app, run),
        (Stage::Welcome, _) => super::welcome::draw(frame, head, app),
        (Stage::Quick, _) => super::quick::draw(frame, head, app),
        (Stage::Step(at), _) => super::steps::draw(frame, head, app, at),
        (Stage::Request, _) => super::certs::draw_request(frame, head, app),
        (Stage::Add(which), _) => super::certs::draw_add(frame, head, app, which),
        (Stage::Running, run) => draw_running(frame, head, app, run.as_ref()),
        (Stage::Finished, None) => {
            frame::draw(frame, &app.theme, head, None, &app.bar(Bar::act(&[])));
        }
    }
}

fn draw_running<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: Option<&Run>) {
    let t = &app.theme;
    let Some(run) = run else {
        frame::draw(frame, t, head, Some("Installing"), &app.bar(Bar::act(&[])));
        return;
    };
    let titles: Vec<String> = run.work.labels.iter().map(|(t, _)| t.clone()).collect();
    let running = run
        .current()
        .and_then(|c| run.work.labels.iter().position(|(_, r)| r.contains(&c)));
    // The assistant never stops the run: its row shows a note, not a cross.
    let states: Vec<Option<StepState>> = label_states(run)
        .into_iter()
        .zip(&run.work.labels)
        .map(|(state, (_, calls))| match state {
            Some(s) if !s.finished() && calls.clone().all(|i| is_model(&run.work.calls[i])) => {
                Some(StepState::Skipped(s.detail().to_owned()))
            }
            other => other,
        })
        .collect();
    let bar = match running {
        Some(i) => Bar::Busy {
            text: format!("Step {} of {}: {}", i + 1, titles.len(), titles[i]),
            tick: app.tick_count,
        },
        None if run.running() => Bar::Busy {
            text: "Finishing…".into(),
            tick: app.tick_count,
        },
        None => Bar::act(&[("Enter", "Try again")]),
    };
    let area = frame::draw(frame, t, head, Some("Installing"), &app.bar(bar));
    let room = usize::from(area.height);
    // A stop keeps its whole reason: the rows fold to make room for it.
    let stop = run.stopped_at().map(|at| {
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        failure(t, why, "Try again goes on from this step.")
    });
    let mut lines = Vec::new();
    let room = match &stop {
        Some(block) => room.saturating_sub(block.len() + 1),
        None => {
            lines.push(Line::raw(""));
            room.saturating_sub(1)
        }
    };
    lines.extend(steps::lines(
        t,
        &titles,
        &states,
        running,
        app.tick_count,
        room,
    ));
    if let Some(block) = stop {
        lines.push(Line::raw(""));
        lines.extend(block);
    }
    frame.render_widget(Paragraph::new(lines), area);
}
