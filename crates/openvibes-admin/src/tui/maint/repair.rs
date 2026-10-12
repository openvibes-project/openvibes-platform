//! Maintenance › Repair (spec §6; maint1.py): it checks every step first
//! and lists what it found (a report; nothing changes); Fix N problems
//! runs every step in repair mode (never a new CA), then checks again;
//! Check again re-reads. The steps that pass fold into one line (plan
//! decision 15). A half-done update blocks repair runs (`job_guard`):
//! Repair says so and offers no Fix until the update is finished.

use std::time::Instant;

use platform_host::{Host, Step, StepState};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::failure;
use crate::tui::{
    app::{App, Key},
    run::{Call, Kind, Run, Work},
    ui::{
        bar::{Bar, SPINNER},
        frame,
        list::{self, Row},
        logo::Header,
        steps,
    },
};

/// `setup-status`: `STEP<TAB>STATE<TAB>DETAIL` per line.
pub fn parse(out: &str) -> Vec<(Step, StepState)> {
    out.lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once('\t')?;
            Some((Step::parse(name)?, StepState::parse(rest)?))
        })
        .collect()
}

fn problem(state: &StepState) -> bool {
    matches!(
        state,
        StepState::Todo | StepState::Failed(_) | StepState::Waiting(_)
    )
}

pub fn check_work() -> Work {
    Work::new(Kind::Check, vec![Call::Status])
}

pub fn fix_work() -> Work {
    Work::new(
        Kind::Fix,
        Step::ALL
            .iter()
            .map(|s| Call::Repair(*s))
            .chain([Call::Status])
            .collect(),
    )
}

enum Mode<'a> {
    /// No check yet (the password was not given).
    Waiting,
    Checking,
    Fixing(&'a Run),
    /// The fix stopped at this step.
    Stopped(&'a Run, usize),
    Report(Vec<(Step, StepState)>, Instant),
    /// The check itself failed (wrong password, helper error); whether it
    /// was the check after a fix.
    Failed(String, bool),
}

/// The newer of the last check and the last fix decides what shows.
fn mode<H: Host>(app: &App<H>) -> Mode<'_> {
    let fix = app.run.as_ref().filter(|r| r.work.kind == Kind::Fix);
    let check = app.load.as_ref().filter(|r| r.work.kind == Kind::Check);
    if let Some(run) = fix.filter(|r| r.running()) {
        return Mode::Fixing(run);
    }
    if check.is_some_and(Run::running) {
        return Mode::Checking;
    }
    let newest = match (check, fix) {
        (Some(c), Some(f)) if c.ended < f.ended => Some(f),
        (Some(c), _) => Some(c),
        (None, f) => f,
    };
    let Some(run) = newest else {
        return Mode::Waiting;
    };
    let last = run.work.calls.len() - 1;
    match (run.stopped_at(), &run.states[last]) {
        (Some(at), _) if at < last => Mode::Stopped(run, at),
        (_, Some(StepState::Done(out))) => match parse(out) {
            steps if steps.is_empty() => Mode::Failed(
                format!("unexpected helper output: {}", out.trim()),
                run.work.kind == Kind::Fix,
            ),
            steps => Mode::Report(steps, run.ended.unwrap_or(run.started)),
        },
        (_, Some(other)) => Mode::Failed(other.detail().to_owned(), run.work.kind == Kind::Fix),
        (_, None) => Mode::Waiting,
    }
}

fn ago(at: Instant) -> String {
    match at.elapsed().as_secs() / 60 {
        0 => "checked just now".into(),
        1 => "checked a minute ago".into(),
        n => format!("checked {n} minutes ago"),
    }
}

/// The report's actions: Fix (unless an update is half done), Check again.
fn entries(steps: &[(Step, StepState)], half_done: bool) -> Vec<(String, String)> {
    let problems: Vec<&str> = steps
        .iter()
        .filter(|(_, s)| problem(s))
        .map(|(s, _)| s.title())
        .collect();
    let mut out = Vec::new();
    if !problems.is_empty() && !half_done {
        let n = problems.len();
        let name = if n == 1 {
            "Fix 1 problem".to_owned()
        } else {
            format!("Fix {n} problems")
        };
        out.push((name, problems.join(", ").to_lowercase()));
    }
    out.push(("Check again".to_owned(), String::new()));
    out
}

fn titles() -> Vec<String> {
    Step::ALL.iter().map(|s| s.title().to_owned()).collect()
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let half_done = app.half_done.is_some();
    let mode = mode(app);
    let bar = match &mode {
        Mode::Fixing(run) => match run.current() {
            Some(i) if i < Step::ALL.len() => Bar::Busy {
                text: format!(
                    "Step {} of {}: {}",
                    i + 1,
                    Step::ALL.len(),
                    Step::ALL[i].title()
                ),
                tick: app.tick_count,
            },
            _ => Bar::Busy {
                text: "Checking again…".into(),
                tick: app.tick_count,
            },
        },
        Mode::Checking => Bar::Busy {
            text: "Checking every step…".into(),
            tick: app.tick_count,
        },
        Mode::Stopped(..) | Mode::Failed(..) => Bar::act(&[("Enter", "Try again")]),
        Mode::Report(steps, _) => {
            let label = entries(steps, half_done)
                .get(app.nav.row)
                .map(|(n, _)| n.clone())
                .unwrap_or_default();
            Bar::keys(&[("Enter", label.as_str())])
        }
        Mode::Waiting => Bar::act(&[("Enter", "Check every step")]),
    };
    let title = if matches!(mode, Mode::Fixing(_)) {
        "Repairing"
    } else {
        "Repair"
    };
    let area = frame::draw(frame, t, head, Some(title), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    match mode {
        Mode::Waiting => lines.push(Line::styled(
            "    Checking every step needs your password.",
            t.dim(),
        )),
        Mode::Checking => lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(SPINNER[app.tick_count % SPINNER.len()], t.teal()),
            Span::raw(" Checking every step…"),
        ])),
        Mode::Fixing(run) => lines.extend(steps::lines(
            t,
            &titles(),
            &run.states,
            run.current(),
            app.tick_count,
            10,
        )),
        Mode::Stopped(run, at) => {
            lines.extend(steps::lines(t, &titles(), &run.states, None, 0, 7));
            lines.push(Line::raw(""));
            let why = run.states[at].as_ref().map_or("", StepState::detail);
            lines.extend(failure(
                t,
                why,
                "Nothing was broken: the steps before it are in order. Try again goes on from here.",
            ));
        }
        Mode::Failed(why, after_fix) => lines.extend(failure(
            t,
            &why,
            if after_fix {
                "The repair ran, but checking again failed. Nothing was broken: Try again checks once more."
            } else {
                "Nothing was changed. Try again checks once more."
            },
        )),
        Mode::Report(steps, at) => {
            let problems: Vec<&(Step, StepState)> =
                steps.iter().filter(|(_, s)| problem(s)).collect();
            let n = problems.len();
            lines.push(if n == 0 {
                Line::from(vec![
                    Span::raw("    "),
                    Span::styled("● Everything is in order", t.green()),
                    Span::styled(format!(" · {}", ago(at)), t.dim()),
                ])
            } else {
                let found = if n == 1 {
                    "1 problem found".to_owned()
                } else {
                    format!("{n} problems found")
                };
                Line::from(vec![
                    Span::raw("    "),
                    Span::styled(found, t.yellow()),
                    Span::styled(format!(" · {}", ago(at)), t.dim()),
                ])
            });
            lines.push(Line::raw(""));
            for (step, state) in &problems {
                let detail = if state.detail().is_empty() {
                    state.label()
                } else {
                    state.detail()
                };
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled("▲ ", t.yellow()),
                    Span::raw(format!("{:<22} ", step.title())),
                    Span::styled(detail.to_owned(), t.dim()),
                ]));
            }
            let fine = steps.len() - n;
            let others = if n == 0 { "steps" } else { "other steps" };
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled("✓ ", t.green()),
                Span::raw(format!("{fine} {others} in order")),
            ]));
            if half_done && n > 0 {
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled("An update stopped half way:", t.yellow()),
                    Span::raw(" finish it in Update OpenVIBES first."),
                ]));
            }
            lines.push(Line::raw(""));
            let rows: Vec<Row> = entries(&steps, half_done)
                .iter()
                .map(|(n, v)| Row::entry(n, v))
                .collect();
            let room = area.height.saturating_sub(lines.len() as u16);
            let height = u16::try_from(rows.len() * 2 + 1)
                .unwrap_or(u16::MAX)
                .min(room);
            let mut scroll = app.nav.scroll.get();
            lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, height, 22));
            app.nav.scroll.set(scroll);
        }
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// What Enter does now, owned so the app can be changed after.
enum Act {
    None,
    Retry(Work, usize),
    Check,
    Rows(usize, bool),
}

impl<H: Host> App<H> {
    /// Opens Repair: it checks first (unless a fix is running).
    pub(super) fn open_repair(&mut self) {
        self.nav.row = 0;
        if !self
            .run
            .as_ref()
            .is_some_and(|r| r.work.kind == Kind::Fix && r.running())
        {
            self.begin(check_work(), 0);
        }
    }

    pub(super) fn repair_key(&mut self, key: Key) {
        let half_done = self.half_done.is_some();
        let act = match mode(self) {
            Mode::Stopped(run, at) => Act::Retry(run.work.clone(), at),
            Mode::Failed(..) | Mode::Waiting => Act::Check,
            Mode::Report(steps, _) => Act::Rows(
                entries(&steps, half_done).len(),
                steps.iter().any(|(_, s)| problem(s)) && !half_done,
            ),
            Mode::Checking | Mode::Fixing(_) => Act::None,
        };
        match act {
            Act::Retry(work, at) if key == Key::Enter => self.begin(work, at),
            Act::Check if key == Key::Enter => self.begin(check_work(), 0),
            Act::Rows(count, fix) => {
                if self.move_row(key, count) || key != Key::Enter {
                    return;
                }
                if fix && self.nav.row == 0 {
                    self.begin(fix_work(), 0);
                } else {
                    self.nav.row = 0;
                    self.begin(check_work(), 0);
                }
            }
            _ => {}
        }
    }

    /// A Fix run ended: its result in the bar.
    pub(super) fn repair_ended(&mut self) {
        let Some(run) = self
            .run
            .as_ref()
            .filter(|r| r.work.kind == Kind::Fix && !r.running())
        else {
            return;
        };
        let last = run.work.calls.len() - 1;
        if let Some(StepState::Done(out)) = &run.states[last] {
            let left = parse(out).iter().filter(|(_, s)| problem(s)).count();
            self.outcome = Some(match left {
                0 => (
                    true,
                    format!("Repaired: everything is in order ({})", run.took()),
                ),
                1 => (false, format!("1 problem left ({})", run.took())),
                n => (false, format!("{n} problems left ({})", run.took())),
            });
        }
    }
}
