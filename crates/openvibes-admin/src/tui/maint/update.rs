//! Maintenance › Update OpenVIBES (spec §6; maint1.py, flows.py): what is
//! installed and what is new; Back up first (off by default, then your
//! last choice) with its folder; Update now with the standard question;
//! six steps; one result line. A failure while stopping or installing
//! starts the services again; a half-done update can be finished.

use std::path::Path;

use platform_host::{Host, PackageUpdate, StepState, UpdateStep};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Page, Then, failure, folder};
use crate::tui::{
    app::{App, Key, Question},
    nav::Screen,
    run::{Call, Kind, Rescue, Run, Work},
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
        steps,
    },
};

pub const STEPS: [&str; 6] = [
    "Back up",
    "Stop services",
    "Install packages",
    "Update the database",
    "Start services",
    "Ready",
];
const RELEASES: &str = "github.com/openvibes-project/openvibes-platform/releases/tag/";

/// The kind of a job left half done (`update`, `uninstall`): the first
/// line of the helper's mark in /run, readable by all.
pub fn half_done(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join("run/openvibes-admin/job")).ok()?;
    let kind = text.lines().next().unwrap_or_default().trim();
    (!kind.is_empty()).then(|| kind.to_owned())
}

/// A half-done uninstall was Remove everything (the mark's second line).
pub fn half_done_everything(root: &Path) -> bool {
    std::fs::read_to_string(root.join("run/openvibes-admin/job"))
        .is_ok_and(|text| text.lines().nth(1) == Some("everything"))
}

/// The update's calls (from Stop when finishing a half-done one). A stop
/// while stopping or installing starts the services again, then runs
/// Ready (it starts the agent and ends the half-done mark). Not when
/// finishing: new packages must not be started on the old schema.
pub fn work(to: &str, others: Option<String>, backup: Option<&str>, finish: bool) -> Work {
    let mut args = vec!["--remember-choice".to_owned()];
    if let Some(file) = backup {
        args.extend(["--backup".to_owned(), file.to_owned()]);
    }
    let skip = usize::from(finish);
    let calls = UpdateStep::ALL[skip..]
        .iter()
        .map(|s| Call::Update(*s, args.clone()))
        .collect();
    let mut work = Work::new(
        Kind::Update {
            to: to.to_owned(),
            others,
        },
        calls,
    );
    work.rescue = (!finish).then(|| Rescue {
        from: 1,
        to: 3,
        calls: vec![
            Call::Update(UpdateStep::Start, args.clone()),
            Call::Update(UpdateStep::Ready, args),
        ],
    });
    work
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Choice {
    First,
    Folder,
    Update,
    WhatsNew,
}

/// What Update now installs, and whether it finishes a half-done update.
fn target<H: Host>(app: &App<H>) -> Option<(String, bool)> {
    if app.half_done.as_deref() == Some("update") {
        let to = app
            .update
            .clone()
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
        return Some((to, true));
    }
    // Any OpenVIBES package newer, not only the admin: the version is the
    // admin's when it has one, else the installed one.
    (app.update.is_some() || updates_available(&app.packages))
        .then(|| (installed_or(&app.update), false))
}

/// "agent 0.2.9, rules 0.1.2": the newer packages, when the admin itself
/// is not newer (then the question says "Update to X", X being the admin version).
fn others<H: Host>(app: &App<H>) -> Option<String> {
    let Some(Ok(list)) = &app.packages else {
        return None;
    };
    if app.update.is_some() || app.half_done.as_deref() == Some("update") {
        return None;
    }
    let names: Vec<String> = list
        .iter()
        .filter(|p| p.name.starts_with("openvibes-"))
        .filter_map(|p| {
            let version = p.available.as_deref()?.split('-').next()?;
            Some(format!(
                "{} {version}",
                p.name.trim_start_matches("openvibes-")
            ))
        })
        .collect();
    (!names.is_empty()).then(|| names.join(", "))
}

fn installed_or(newer: &Option<String>) -> String {
    newer
        .clone()
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned())
}

/// Whether the package check found any OpenVIBES package with a newer version.
pub fn updates_available(packages: &Option<Result<Vec<PackageUpdate>, String>>) -> bool {
    matches!(packages, Some(Ok(list))
        if list.iter().any(|p| p.name.starts_with("openvibes-") && p.available.is_some()))
}

fn choices<H: Host>(app: &App<H>) -> Vec<Choice> {
    let mut out = Vec::new();
    match target(app) {
        Some((_, false)) => {
            out.push(Choice::First);
            if app.maint.first {
                out.push(Choice::Folder);
            }
            out.push(Choice::Update);
        }
        Some((_, true)) => out.push(Choice::Update),
        None => {}
    }
    out.push(Choice::WhatsNew);
    out
}

fn update_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Update { .. }))
}

fn row<H: Host>(app: &App<H>, choice: Choice) -> Row {
    let t = &app.theme;
    match choice {
        Choice::First => {
            let mark = if app.maint.first {
                Span::styled("[x]", t.green())
            } else {
                Span::raw("[ ]")
            };
            let value = match (&app.maint.memory.folder, app.maint.first) {
                (_, true) => String::new(),
                (Some(folder), false) => folder.clone(),
                (None, false) => "no folder chosen yet".into(),
            };
            Row::Entry {
                name: vec![mark, Span::raw(" Back up first")],
                value: vec![Span::styled(value, t.dim())],
            }
        }
        Choice::Folder => Row::Entry {
            name: vec![Span::raw("Save in folder")],
            value: folder::value(t, &app.maint.folder),
        },
        Choice::Update if target(app).is_some_and(|(_, finish)| finish) => Row::entry(
            "Finish the update",
            "the services are stopped until it ends",
        ),
        Choice::Update => Row::entry("Update now", "services stop while it runs"),
        Choice::WhatsNew => Row::entry("What's new", "the release notes"),
    }
}

fn help<H: Host>(app: &App<H>, choice: Choice) -> Line<'static> {
    let t = &app.theme;
    let dim = |text: String| Line::styled(format!("    {text}"), t.dim());
    match choice {
        Choice::First if app.maint.memory.first => {
            dim("Ticked because you backed up last time · a new file each time.".into())
        }
        Choice::First => dim("Off unless you chose it last time.".into()),
        Choice::Folder => folder::help(t, &app.maint.folder),
        // The folder, not the file: the file system is not read per frame.
        Choice::Update if app.maint.first && app.maint.folder.ok() => dim(format!(
            "Backs up to {} first, a new file each time.",
            app.maint.folder.text.trim()
        )),
        Choice::Update => {
            dim("Stops the services, installs the packages, updates the database.".into())
        }
        Choice::WhatsNew => dim("Every package's version, and where the release notes are.".into()),
    }
}

fn info<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    let t = &app.theme;
    let installed = Span::raw(format!("    v{} installed · ", env!("CARGO_PKG_VERSION")));
    let first = match (&app.packages, &app.update) {
        (_, Some(to)) => Line::from(vec![
            installed,
            Span::styled(format!("{to} available"), t.yellow()),
        ]),
        (None, None) => Line::from(vec![
            installed,
            Span::styled("looking for updates…", t.dim()),
        ]),
        (Some(Err(error)), None) => Line::from(vec![
            installed,
            Span::styled(format!("could not look for updates: {error}"), t.yellow()),
        ]),
        (Some(Ok(_)), None) if updates_available(&app.packages) => Line::from(vec![
            installed,
            Span::styled("updates available", t.yellow()),
        ]),
        (Some(Ok(_)), None) => Line::from(vec![installed, Span::raw("up to date")]),
    };
    let second = if target(app).is_some_and(|(_, finish)| finish) {
        Line::from(vec![
            Span::raw("    "),
            Span::styled("An update stopped half way:", t.yellow()),
            Span::raw(" the services may be stopped until it ends."),
        ])
    } else {
        Line::styled(
            "    Updates every OpenVIBES package on this host, then the database.",
            t.dim(),
        )
    };
    vec![first, second]
}

/// What to do after a stop, by the step it stopped at (counted in STEPS).
fn after(run: &Run, skip: usize) -> String {
    let at = run.stopped_at().unwrap_or(0) + skip;
    match (at, run.rescued(0)) {
        (0, _) => "The services keep running; nothing was changed.".into(),
        // Finishing: no rescue; the old schema must not meet new packages.
        (1 | 2, _) if skip == 1 => "The services stay stopped until the update is finished: \
                                     Try again."
            .into(),
        // Stopped at Stop services: no package was touched.
        (1, _) if (0..2).all(|j| run.rescued(j).is_some_and(StepState::finished)) => {
            "The services are started again; nothing was updated: Try again.".into()
        }
        (2, _) if (0..2).all(|j| run.rescued(j).is_some_and(StepState::finished)) => {
            "The services are started again; the packages may be partly updated: Try again.".into()
        }
        (1 | 2, _) if (0..2).all(|j| run.rescued(j).is_some()) => {
            let why = (0..2)
                .filter_map(|j| run.rescued(j))
                .find(|s| !s.finished())
                .map_or("", StepState::detail);
            format!("The services could not be started again ({why}): see Status.")
        }
        (1 | 2, _) if run.running() => "The services are being started again…".into(),
        (1 | 2, _) => "Nothing more was run: see Status for the services.".into(),
        (3, _) => "The packages are new but the database is not yet: Try again finishes it \
                   (it also puts PostgreSQL back if it is missing). \
                   The services stay stopped until then."
            .into(),
        (4, _) => "Some services did not start: see Status, then Try again.".into(),
        _ => "Everything is updated, but a service is not ready yet: see Status.".into(),
    }
}

/// Where Try again starts: from Stop when the rescue started the services
/// again, else the step that stopped.
fn retry_from(run: &Run, skip: usize) -> usize {
    match run.stopped_at().map(|at| at + skip) {
        None | Some(0) => 0,
        // Services stopped again first, unless finishing (no rescue ran).
        Some(1 | 2) if skip == 0 => 1,
        Some(at) => at - skip,
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = update_run(app) {
        return draw_run(frame, head, app, run);
    }
    let t = &app.theme;
    let choices = choices(app);
    let chosen = choices.get(app.nav.row).copied();
    let bar = match chosen {
        Some(Choice::First) => Bar::keys(&[("Space", "Select/deselect"), ("Enter", "Confirm")]),
        Some(Choice::Folder) if app.maint.folder.editing() => folder::bar(),
        Some(Choice::Folder) => Bar::keys(&[("Enter", "Choose a folder")]),
        Some(Choice::Update) if target(app).is_some_and(|(_, f)| f) => {
            Bar::keys(&[("Enter", "Finish the update")])
        }
        Some(Choice::Update) => Bar::keys(&[("Enter", "Update now")]),
        Some(Choice::WhatsNew) | None => Bar::keys(&[("Enter", "What's new")]),
    };
    let area = frame::draw(frame, t, head, Some("Update OpenVIBES"), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    lines.extend(info(app));
    let rows: Vec<Row> = choices.iter().map(|c| row(app, *c)).collect();
    let room = area
        .height
        .saturating_sub(u16::try_from(lines.len() + 1).unwrap_or(u16::MAX));
    let height = u16::try_from(rows.len() * 2 + 1)
        .unwrap_or(u16::MAX)
        .min(room);
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, height, 24));
    app.nav.scroll.set(scroll);
    if let Some(choice) = chosen {
        lines.push(help(app, choice));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_run<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let Kind::Update { to, .. } = &run.work.kind else {
        return;
    };
    let skip = UpdateStep::ALL.len() - run.work.calls.len();
    let titles: Vec<String> = STEPS[skip..].iter().map(|s| (*s).to_owned()).collect();
    let open = format!("Open {to}");
    let bar = match run.current() {
        Some(i) => Bar::Busy {
            text: format!("Step {} of {}: {}", i + 1, titles.len(), titles[i]),
            tick: app.tick_count,
        },
        None if run.running() => Bar::Busy {
            text: "Starting the services again…".into(),
            tick: app.tick_count,
        },
        None if run.ok() => Bar::only(&[("Enter", open.as_str())]),
        None => Bar::act(&[("Enter", "Try again")]),
    };
    let area = frame::draw(frame, t, head, Some(&run.work.kind.doing()), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    lines.extend(steps::lines(
        t,
        &titles,
        &run.states,
        run.current(),
        app.tick_count,
        6,
    ));
    lines.push(Line::raw(""));
    if run.ok() {
        lines.push(Line::styled(
            format!(
                "    ✓ {} · everything is ready{}",
                run.work.kind.done(),
                run.took()
            ),
            t.green(),
        ));
    } else if let Some(at) = run.stopped_at() {
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        lines.extend(failure(t, why, &after(run, skip)));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw_whats_new<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let area = frame::draw(frame, t, head, Some("What's new"), &app.bar(Bar::act(&[])));
    let mut lines = vec![Line::raw("")];
    match &app.packages {
        Some(Ok(packages)) => lines.extend(packages.iter().map(|p| {
            let change = p.available.as_ref().map_or_else(
                || format!("{} · up to date", p.installed),
                |a| format!("{} → {a}", p.installed),
            );
            Line::raw(format!("    {:<26} {change}", p.name))
        })),
        Some(Err(error)) => lines.push(Line::styled(
            format!("    could not look for updates: {error}"),
            t.yellow(),
        )),
        None => lines.push(Line::styled("    looking for updates…", t.dim())),
    }
    let version = app
        .update
        .clone()
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
    lines.push(Line::raw(""));
    // On a line of its own, without the scheme: it must fit 80 columns.
    lines.push(Line::styled("    Release notes:", t.dim()));
    lines.push(Line::raw(format!("    {RELEASES}v{version}")));
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn update_key(&mut self, key: Key) {
        if self.maint.folder.editing() {
            return self.folder_key(key);
        }
        if let Some(run) = update_run(self) {
            if run.running() || key != Key::Enter {
                return;
            }
            if run.ok() {
                self.reopen = true;
            } else {
                let skip = UpdateStep::ALL.len() - run.work.calls.len();
                let (work, from) = (run.work.clone(), retry_from(run, skip));
                self.begin(work, from);
            }
            return;
        }
        let choices = choices(self);
        if self.move_row(&key, choices.len()) {
            return;
        }
        match (choices.get(self.nav.row), key) {
            (Some(Choice::First), Key::Char(' ')) => self.maint.first = !self.maint.first,
            (Some(Choice::Folder), Key::Enter) => self.maint.folder.edit(),
            (Some(Choice::WhatsNew), Key::Enter) => self.nav.go(Screen::Maint(Page::WhatsNew)),
            (Some(Choice::First | Choice::Update), Key::Enter) => self.ask_update(),
            _ => {}
        }
    }

    fn ask_update(&mut self) {
        let Some((to, finish)) = target(self) else {
            return;
        };
        if self.maint.first && !finish {
            // The folder's slow check may be due: take it before judging.
            self.poll_folder(std::time::Instant::now());
            if !self.maint.folder.ok() {
                let why = if self.maint.folder.pending() {
                    "Wait: the folder is still being checked"
                } else {
                    "Choose a folder for the backup first"
                };
                self.outcome = Some((false, why.into()));
                self.nav.row = 1;
                return;
            }
        }
        let (text, detail) = if finish {
            ("Finish the update?".to_owned(), "the services start again")
        } else {
            (
                match others(self) {
                    Some(what) => format!("Install updates ({what})?"),
                    None => format!("Update to {to}?"),
                },
                "services stop",
            )
        };
        self.question = Some((
            Question::Maint {
                text,
                detail: detail.into(),
                then: Then::Update,
            },
            true,
        ));
    }

    pub(super) fn update_yes(&mut self) {
        let Some((to, finish)) = target(self) else {
            return;
        };
        let file = (self.maint.first && !finish).then(|| self.backup_file());
        self.begin(work(&to, others(self), file.as_deref(), finish), 0);
    }
}
