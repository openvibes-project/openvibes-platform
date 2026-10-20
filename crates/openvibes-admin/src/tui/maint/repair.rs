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

use super::{Page, failure};
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Do {
    Finish,
    Fix,
    Again,
}

/// The report's actions. A half-done update offers Finish the update first
/// and no Fix; another half-done job offers no Fix either.
fn entries(steps: &[(Step, StepState)], half: Option<&str>) -> Vec<(Do, String, String)> {
    let problems: Vec<&str> = steps
        .iter()
        .filter(|(_, s)| problem(s))
        .map(|(s, _)| s.title())
        .collect();
    let mut out = Vec::new();
    if let Some((name, page)) = half.and_then(finishing) {
        out.push((Do::Finish, name.into(), page.title().into()));
    } else if !problems.is_empty() && half.is_none() {
        let n = problems.len();
        let name = if n == 1 {
            "Fix 1 problem".to_owned()
        } else {
            format!("Fix {n} problems")
        };
        out.push((Do::Fix, name, problems.join(", ").to_lowercase()));
    }
    out.push((Do::Again, "Check again".into(), String::new()));
    out
}

/// The entry and page that finish a half-done job.
pub(super) fn finishing(kind: &str) -> Option<(&'static str, Page)> {
    match kind {
        "update" => Some(("Finish the update", Page::Update)),
        "uninstall" => Some(("Finish the uninstall", Page::Uninstall)),
        _ => None,
    }
}

/// What a half-done job is, and what finishes it.
pub(super) fn half_note(kind: &str) -> (String, &'static str) {
    match kind {
        "update" => ("An update stopped half way:".into(), " finish it first."),
        "uninstall" => (
            "An uninstall stopped half way:".into(),
            " finish it from Maintenance › Uninstall first.",
        ),
        other => (format!("An {other} stopped half way:"), " finish it first."),
    }
}

fn titles() -> Vec<String> {
    Step::ALL.iter().map(|s| s.title().to_owned()).collect()
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let half = app.half_done.as_deref();
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
            let label = entries(steps, half)
                .get(app.nav.row)
                .map(|(_, n, _)| n.clone())
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
            if let (Some(kind), true) = (half, n > 0) {
                let (what, todo) = half_note(kind);
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(what, t.yellow()),
                    Span::raw(todo),
                ]));
            }
            // The list's own hint line is the one empty line above the actions.
            let rows: Vec<Row> = entries(&steps, half)
                .iter()
                .map(|(_, n, v)| Row::entry(n, v))
                .collect();
            let room = area
                .height
                .saturating_sub(u16::try_from(lines.len()).unwrap_or(u16::MAX));
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
    Rows(Vec<Do>),
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
        let half = self.half_done.clone();
        let act = match mode(self) {
            Mode::Stopped(run, at) => Act::Retry(run.work.clone(), at),
            Mode::Failed(..) | Mode::Waiting => Act::Check,
            Mode::Report(steps, _) => Act::Rows(
                entries(&steps, half.as_deref())
                    .into_iter()
                    .map(|e| e.0)
                    .collect(),
            ),
            Mode::Checking | Mode::Fixing(_) => Act::None,
        };
        match act {
            Act::Retry(work, at) if key == Key::Enter => self.begin(work, at),
            Act::Check if key == Key::Enter => self.begin(check_work(), 0),
            Act::Rows(rows) => {
                if self.move_row(key, rows.len()) || key != Key::Enter {
                    return;
                }
                match rows.get(self.nav.row) {
                    Some(Do::Fix) => self.begin(fix_work(), 0),
                    Some(Do::Finish) => {
                        if let Some((_, page)) = half.as_deref().and_then(finishing) {
                            self.open_page(page);
                        }
                    }
                    _ => {
                        self.nav.row = 0;
                        self.begin(check_work(), 0);
                    }
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
        let took = run.took();
        self.outcome = match &run.states[last] {
            Some(StepState::Done(out)) => {
                match parse(out).iter().filter(|(_, s)| problem(s)).count() {
                    _ if parse(out).is_empty() => Some((
                        false,
                        format!("The repair ran, but checking again failed ({took})"),
                    )),
                    0 => Some((true, format!("Repaired: everything is in order ({took})"))),
                    1 => Some((false, format!("1 problem left ({took})"))),
                    n => Some((false, format!("{n} problems left ({took})"))),
                }
            }
            Some(_) if run.stopped_at() == Some(last) => Some((
                false,
                format!("The repair ran, but checking again failed ({took})"),
            )),
            _ => return,
        };
    }
}
