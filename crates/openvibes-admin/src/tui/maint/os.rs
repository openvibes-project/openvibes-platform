//! Maintenance › Operating system (spec §6; os2.py, osupdate.py): the
//! distribution, kernel and last check, what dnf says is waiting, and the
//! actions as entries: Update everything (asks first), Check again,
//! Restart now. A running update goes on when the screen is left. The
//! counts are the last check's (`os-check` keeps them for everyone to
//! read); only the actions ask for the password.

use std::time::{SystemTime, UNIX_EPOCH};

use platform_host::{
    Host, StepState,
    os_updates::{OsInfo, OsUpdates, short_kernel},
};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Then, failure};
use crate::tui::{
    app::{App, Key, Question},
    kind::OsAction,
    run::{Call, Kind, Run, Work},
    ui::{
        bar::{Bar, SPINNER},
        frame,
        list::{self, Row},
        logo::Header,
    },
};

/// The page's entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Choice {
    Update,
    Check,
    Restart,
    /// After an update that needs a restart: leave it for now.
    Later,
}

fn os_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Os(_)))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// "just now", "10 min ago", "3 hours ago", "2 days ago".
pub(super) fn ago(seconds: i64) -> String {
    let (n, unit) = match seconds.max(0) {
        s if s < 60 => return "just now".into(),
        s if s < 3600 => return format!("{} min ago", s / 60),
        s if s < 86_400 => (s / 3600, "hour"),
        s => (s / 86_400, "day"),
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

/// "AlmaLinux 9.6" from "AlmaLinux 9.6 (Sage Margay)".
fn short(name: &str) -> &str {
    name.split(" (").next().unwrap_or(name)
}

/// The Maintenance menu's value for this entry.
pub(super) fn summary<H: Host>(host: &H) -> String {
    let Some(os) = host.os_info() else {
        return "no package manager OpenVIBES knows".into();
    };
    let name = short(&os.name);
    match os.updates {
        None => format!("{name} · not checked yet"),
        Some(OsUpdates {
            total: 0, restart, ..
        }) => {
            let rest = if restart {
                "restart needed"
            } else {
                "up to date"
            };
            format!("{name} · {rest}")
        }
        Some(found) if found.security > 0 => format!(
            "{name} · {} updates, {} for security",
            found.total, found.security
        ),
        Some(found) => format!("{name} · {} updates", found.total),
    }
}

fn plural(n: u32, what: &str) -> String {
    format!("{n} {what}{}", if n == 1 { "" } else { "s" })
}

fn choices(os: &OsInfo) -> Vec<Choice> {
    let found = os.updates.unwrap_or_default();
    let mut all = Vec::new();
    // An update started elsewhere (or before this screen was left) goes on.
    if os.running {
        return all;
    }
    if found.total > 0 {
        all.push(Choice::Update);
    }
    all.push(Choice::Check);
    if found.restart {
        all.push(Choice::Restart);
    }
    all
}

fn row(os: &OsInfo, choice: Choice) -> Row {
    let found = os.updates.unwrap_or_default();
    match choice {
        Choice::Update => {
            let then = if found.kernel || found.restart {
                ", then a restart"
            } else {
                ""
            };
            Row::entry(
                "Update everything",
                &format!("{}{then}", plural(found.total, "package")),
            )
        }
        Choice::Check => Row::entry("Check again", ""),
        Choice::Restart => Row::entry("Restart now", "the new kernel starts then"),
        Choice::Later => Row::entry("Later", "OpenVIBES keeps running"),
    }
}

fn action(choice: Choice) -> &'static str {
    match choice {
        Choice::Update => "Update everything",
        Choice::Check => "Check again",
        Choice::Restart => "Restart now",
        Choice::Later => "Later",
    }
}

fn info<H: Host>(app: &App<H>, os: &OsInfo) -> Vec<Line<'static>> {
    let t = &app.theme;
    let checked = os.updates.map_or_else(
        || "not checked yet".to_owned(),
        |found| format!("checked {}", ago(now() - found.checked_at)),
    );
    let head = format!("    {} · kernel {}", os.name, short_kernel(&os.kernel));
    // 80 columns, and the kernel string of a real host can be long.
    let first = if head.chars().count() + checked.chars().count() + 3 <= 76 {
        vec![Line::raw(format!("{head} · {checked}"))]
    } else {
        vec![Line::raw(head), Line::raw(format!("    {checked}"))]
    };
    let second = match os.updates {
        None => Line::styled("    Check again asks dnf what is waiting.", t.dim()),
        Some(found) if found.total > 0 => {
            let mut spans = vec![
                Span::styled("    ▲ ", t.yellow()),
                Span::raw(format!("{} available", plural(found.total, "update"))),
            ];
            if found.security > 0 {
                spans.push(Span::raw(", "));
                spans.push(Span::styled(
                    format!("{} for security", found.security),
                    t.yellow(),
                ));
            }
            if found.kernel {
                spans.push(Span::raw(" · includes a new kernel"));
            }
            Line::from(spans)
        }
        Some(found) if found.restart => Line::from(vec![
            Span::styled("    ▲ ", t.yellow()),
            Span::raw("A restart is needed for the updates already installed."),
        ]),
        Some(_) => Line::styled("    ✓ Up to date", t.green()),
    };
    let second = if os.running {
        Line::from(vec![
            Span::styled("    ▲ ", t.yellow()),
            Span::raw("An update is running now. Check back in a few minutes."),
        ])
    } else {
        second
    };
    first.into_iter().chain([second]).collect()
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = os_run(app) {
        return draw_run(frame, head, app, run);
    }
    let t = &app.theme;
    let Some(os) = app.maint.os.clone() else {
        let area = frame::draw(
            frame,
            t,
            head,
            Some("Operating system"),
            &app.bar(Bar::act(&[])),
        );
        let lines = failure(
            t,
            "This system has no package manager OpenVIBES knows (dnf).",
            "Update its packages the way this system does.",
        );
        return frame.render_widget(Paragraph::new(lines), area);
    };
    let choices = choices(&os);
    let chosen = choices.get(app.nav.row).copied();
    let bar = Bar::keys(&[("Enter", chosen.map_or("", action))]);
    let area = frame::draw(frame, t, head, Some("Operating system"), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    lines.extend(info(app, &os));
    let rows: Vec<Row> = choices.iter().map(|c| row(&os, *c)).collect();
    let mut scroll = app.nav.scroll.get();
    let height = area
        .height
        .saturating_sub(u16::try_from(lines.len()).unwrap_or(0));
    lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, height, 20));
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

/// How many packages `os-update` says it upgraded (the last field).
fn upgraded(run: &Run) -> Option<u32> {
    run.states
        .first()?
        .as_ref()?
        .detail()
        .rsplit('\t')
        .next()?
        .parse()
        .ok()
}

fn draw_run<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let Kind::Os(what) = &run.work.kind else {
        return;
    };
    let title = "Operating system";
    let spin = SPINNER[app.tick_count % SPINNER.len()];
    let mut lines = vec![Line::raw("")];
    let bar = if run.running() {
        let (now, more) = match what {
            OsAction::Check => (
                "Asking dnf what is waiting…".to_owned(),
                "This takes a moment.",
            ),
            OsAction::Update { packages, .. } => (
                format!("Updating {}…", plural(*packages, "package")),
                "This takes a few minutes. You can leave this screen: it",
            ),
            OsAction::Restart => ("Restarting this host…".to_owned(), "The session ends now."),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("    {spin} "), t.teal()),
            Span::raw(now),
        ]));
        lines.push(Line::styled(format!("    {more}"), t.dim()));
        if matches!(what, OsAction::Update { .. }) {
            lines.push(Line::styled(
                "    carries on and Home shows when it is done.",
                t.dim(),
            ));
        }
        Bar::Busy {
            text: run.work.kind.doing(),
            tick: app.tick_count,
        }
    } else if run.ok() {
        let done = match (what, upgraded(run)) {
            (OsAction::Update { .. }, Some(n)) => format!("{} updated", plural(n, "package")),
            _ => run.work.kind.done(),
        };
        lines.push(Line::styled(
            format!("    ✓ {done}{}", run.took()),
            t.green(),
        ));
        if let (OsAction::Update { kernel, .. }, Some(os)) = (what, &app.maint.os)
            && os.updates.is_some_and(|f| f.restart)
        {
            let reason = if *kernel {
                "the new kernel"
            } else {
                "the updates"
            };
            lines.push(Line::from(vec![
                Span::styled("    ▲ ", t.yellow()),
                Span::raw(format!("A restart is needed for {reason}.")),
            ]));
            lines.push(Line::styled(
                "    OpenVIBES starts again by itself after the restart;",
                t.dim(),
            ));
            lines.push(Line::styled(
                "    agents keep their findings meanwhile.",
                t.dim(),
            ));
            lines.push(Line::raw(""));
            let rows = [row(os, Choice::Restart), row(os, Choice::Later)];
            let mut scroll = list::Scroll::default();
            lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, 5, 20));
        }
        if what == &OsAction::Restart {
            Bar::act(&[])
        } else if app
            .maint
            .os
            .as_ref()
            .is_some_and(|o| o.updates.is_some_and(|f| f.restart))
        {
            let label = if app.nav.row == 0 {
                "Restart now"
            } else {
                "Later"
            };
            Bar::keys(&[("Enter", label)])
        } else {
            Bar::only(&[("Enter", "Back")])
        }
    } else {
        let at = run.stopped_at().unwrap_or(0);
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        lines.extend(failure(
            t,
            why,
            "Nothing else was run. Try again goes on from here.",
        ));
        Bar::act(&[("Enter", "Try again")])
    };
    let area = frame::draw(frame, t, head, Some(title), &app.bar(bar));
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_os(&mut self) {
        self.nav.row = 0;
        // A finished run is not news the next time.
        if os_run(self).is_some_and(|r| !r.running() && r.ok()) {
            self.run = None;
        }
        self.read_os();
    }

    /// Reads the host again, the running unit with it (a process start, so
    /// only here, never per draw).
    pub(super) fn read_os(&mut self) {
        self.maint.os = self.host.os_info().map(|mut os| {
            os.running |= self.host.os_update_running();
            os
        });
    }

    /// The periodic refresh on this page: no own run, so the unit's state
    /// and the counts are read again.
    pub(in crate::tui) fn os_refreshed(&mut self) {
        if os_run(self).is_none() {
            self.read_os();
        }
    }

    /// A run ended: the counts are read again.
    pub(super) fn os_ended(&mut self) {
        if os_run(self).is_none_or(Run::running) {
            return;
        }
        self.read_os();
        // A finished check shows as the page itself, with its new counts.
        if os_run(self).is_some_and(|r| r.ok() && r.work.kind == Kind::Os(OsAction::Check)) {
            self.run = None;
        }
    }

    pub(super) fn os_key(&mut self, key: Key) {
        if let Some((running, ok, work, at)) =
            os_run(self).map(|r| (r.running(), r.ok(), r.work.clone(), r.stopped_at()))
        {
            if running {
                return;
            }
            let restart = ok
                && matches!(work.kind, Kind::Os(OsAction::Update { .. }))
                && self
                    .maint
                    .os
                    .as_ref()
                    .is_some_and(|o| o.updates.is_some_and(|f| f.restart));
            if restart && self.move_row(&key, 2) {
                return;
            }
            if key != Key::Enter {
                return;
            }
            if !ok {
                self.begin(work, at.unwrap_or(0));
            } else if restart && self.nav.row == 0 {
                self.ask_os(Choice::Restart);
            } else {
                self.run = None;
                self.back();
            }
            return;
        }
        let Some(os) = self.maint.os.clone() else {
            return;
        };
        let choices = choices(&os);
        if self.move_row(&key, choices.len()) {
            return;
        }
        if let (Key::Enter, Some(choice)) = (key, choices.get(self.nav.row)) {
            self.ask_os(*choice);
        }
    }

    fn ask_os(&mut self, choice: Choice) {
        if let Some(why) = super::busy(self) {
            self.outcome = Some((false, why));
            return;
        }
        let found = self
            .maint
            .os
            .as_ref()
            .and_then(|o| o.updates)
            .unwrap_or_default();
        match choice {
            Choice::Check => {
                self.begin(Work::new(Kind::Os(OsAction::Check), vec![Call::OsCheck]), 0)
            }
            Choice::Later => self.back(),
            Choice::Update => {
                let detail = if found.kernel || found.restart {
                    "restart after"
                } else {
                    "no restart"
                };
                self.question = Some((
                    Question::Maint {
                        text: format!("Install {}?", plural(found.total, "update")),
                        detail: detail.into(),
                        then: Then::OsUpdate,
                    },
                    true,
                ));
            }
            Choice::Restart => {
                self.question = Some((
                    Question::Maint {
                        text: "Restart this host?".into(),
                        detail: "about 1 minute".into(),
                        then: Then::OsRestart,
                    },
                    false,
                ));
            }
        }
    }

    pub(super) fn os_update_yes(&mut self) {
        let packages = self
            .maint
            .os
            .as_ref()
            .and_then(|o| o.updates)
            .map_or(0, |f| f.total);
        let kernel = self
            .maint
            .os
            .as_ref()
            .and_then(|o| o.updates)
            .is_some_and(|f| f.kernel);
        let kind = Kind::Os(OsAction::Update { packages, kernel });
        self.begin(Work::new(kind, vec![Call::OsUpdate]), 0);
    }

    pub(super) fn os_restart_yes(&mut self) {
        self.begin(
            Work::new(Kind::Os(OsAction::Restart), vec![Call::OsRestart]),
            0,
        );
    }
}
