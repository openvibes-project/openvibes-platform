//! Maintenance › Uninstall (spec §6; maint4.py, backupdefault.py): Keep
//! the data (default) or Remove everything (type the host name, ✓ when it
//! matches; nothing is left behind); Back up first as in Update; the
//! standard question. The tool removes itself last, so once it is done,
//! Enter quits.

use platform_host::{Host, RemoveStep};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Then, failure, folder, uninstall_run::draw as draw_run};
use crate::{
    setup::{base::PG_RECORD, plan::Plan},
    tui::{
        app::{App, Key, Question},
        run::{Call, Kind, Run, Work},
        status::wrap,
        ui::{
            bar::Bar,
            frame,
            list::{self, Row},
            logo::Header,
        },
    },
};

pub fn work(plan: &Plan, everything: bool, backup: Option<&str>) -> Work {
    let components: Vec<&str> = plan.components.iter().map(|c| c.name()).collect();
    let mut args = vec![
        "--components".to_owned(),
        components.join(","),
        "--remember-choice".to_owned(),
    ];
    if let Some(file) = backup {
        args.extend(["--backup".to_owned(), file.to_owned()]);
    }
    if everything {
        args.extend(["--confirm".to_owned(), plan.hostname.clone()]);
    }
    let calls = RemoveStep::ALL
        .iter()
        .map(|s| Call::Remove(*s, args.clone()))
        .collect();
    Work::new(Kind::Uninstall { everything }, calls)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Choice {
    Keep,
    Everything,
    First,
    Folder,
    Confirm,
    Go,
}

fn choices<H: Host>(app: &App<H>) -> Vec<Choice> {
    let mut out = vec![Choice::Keep, Choice::Everything, Choice::First];
    if app.maint.first {
        out.push(Choice::Folder);
    }
    if app.maint.everything {
        out.push(Choice::Confirm);
    }
    out.push(Choice::Go);
    out
}

fn uninstall_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Uninstall { .. }))
}

fn hostname<H: Host>(app: &App<H>) -> String {
    app.maint
        .plan
        .as_ref()
        .map(|p| p.hostname.clone())
        .unwrap_or_default()
}

fn row<H: Host>(app: &App<H>, choice: Choice) -> Row {
    let t = &app.theme;
    let radio = |on: bool| if on { "(•)" } else { "( )" };
    match choice {
        Choice::Keep => Row::entry(
            &format!("{} Keep the data", radio(!app.maint.everything)),
            "remove the programs; data stays for a reinstall",
        ),
        Choice::Everything => Row::entry(
            &format!("{} Remove everything", radio(app.maint.everything)),
            "programs, data, accounts, certificates, settings",
        ),
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
        Choice::Confirm => {
            let host = hostname(app);
            let mut value = vec![Span::raw(app.maint.typed.clone())];
            if app.maint.typing {
                value.push(Span::raw("█"));
            }
            if app.maint.typed == host && !host.is_empty() {
                value.push(Span::styled(" ✓", t.green()));
            }
            Row::Entry {
                name: vec![Span::raw(format!("Type {host} to confirm"))],
                value,
            }
        }
        Choice::Go => Row::entry("Uninstall", ""),
    }
}

/// What PostgreSQL does (approved.md 46): only Remove everything takes
/// it, and only when Setup installed it and nothing else uses it.
fn postgres(everything: bool, recorded: bool, installed: bool) -> &'static str {
    match (everything, recorded, installed) {
        (false, ..) => "PostgreSQL stays installed: keeping the data keeps it.",
        (true, true, false) => {
            "PostgreSQL is not installed: the database is not dropped and /var/lib/pgsql stays."
        }
        (true, true, true) => "PostgreSQL goes too if nothing else uses it: Setup installed it.",
        (true, false, _) => "PostgreSQL stays: Setup did not install it.",
    }
}

fn help<H: Host>(app: &App<H>, choice: Choice) -> Vec<Line<'static>> {
    let t = &app.theme;
    let dim = |text: String| -> Vec<Line<'static>> {
        wrap(&text, 72, 2)
            .into_iter()
            .map(|l| Line::styled(format!("    {l}"), t.dim()))
            .collect()
    };
    match choice {
        Choice::First if app.maint.memory.first => {
            dim("Ticked because you backed up last time.".into())
        }
        Choice::First => dim("Off unless you chose it last time.".into()),
        Choice::Folder => vec![folder::help(t, &app.maint.folder)],
        Choice::Confirm => dim(format!(
            "Type {} exactly; a tick shows when it matches.",
            hostname(app)
        )),
        _ if app.maint.everything => dim(format!(
            "Nothing is left behind: every account, file and firewall change goes. {}",
            postgres(true, app.maint.pg_recorded, app.maint.pg_installed)
        )),
        _ => dim(postgres(false, false, false).into()),
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = uninstall_run(app) {
        return draw_run(frame, head, app, run);
    }
    let t = &app.theme;
    let choices = choices(app);
    let chosen = choices.get(app.nav.row).copied();
    let host = hostname(app);
    let bar = match chosen {
        Some(Choice::Folder) if app.maint.folder.editing() => folder::bar(),
        Some(Choice::Folder) => Bar::keys(&[("Enter", "Choose a folder")]),
        Some(Choice::Confirm) if app.maint.typing => {
            Bar::edit("Type the host name", &host, &[("Enter", "Done")])
        }
        Some(Choice::Confirm) => Bar::keys(&[("Enter", "Type the host name")]),
        Some(Choice::Go) => Bar::keys(&[("Enter", "Uninstall")]),
        _ => Bar::keys(&[("Space", "Select/deselect"), ("Enter", "Confirm")]),
    };
    let area = frame::draw(frame, t, head, Some("Uninstall"), &app.bar(bar));
    let rows: Vec<Row> = choices.iter().map(|c| row(app, *c)).collect();
    // The help line(s) sit directly under the list: it gets what they leave.
    let below = match (&app.maint.plan_error, chosen) {
        (None, Some(choice)) => help(app, choice),
        _ => Vec::new(),
    };
    // One empty line stays above the bar; a plan error's text is wrapped
    // later, so it keeps four lines.
    let kept = if app.maint.plan_error.is_some() {
        4
    } else {
        below.len() + 1
    };
    let room = area
        .height
        .saturating_sub(u16::try_from(kept).unwrap_or(u16::MAX));
    let height = u16::try_from(rows.len() * 2 + 1)
        .unwrap_or(u16::MAX)
        .min(room);
    // Whole entries (two lines each) plus the two hint lines: an even
    // height would leave a second empty line above the help.
    let height = if height % 2 == 0 { height - 1 } else { height };
    let mut scroll = app.nav.scroll.get();
    let mut lines = list::lines(t, &rows, app.nav.row, &mut scroll, height, 23);
    app.nav.scroll.set(scroll);
    if let Some(why) = &app.maint.plan_error {
        lines.extend(failure(t, why, "Nothing was removed."));
    } else {
        lines.extend(below);
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_uninstall(&mut self) {
        // A finished-but-failed run's page is a new start; a done one never gets here.
        if self
            .run
            .as_ref()
            .is_some_and(|r| !r.running() && matches!(r.work.kind, Kind::Uninstall { .. }))
        {
            self.run = None;
        }
        self.load_backup_choice();
        // A half-done Remove everything goes on as one, without a backup:
        // its database may be gone (review I3).
        self.maint.everything = super::update::half_done_everything(&self.root);
        if self.maint.everything {
            self.maint.first = false;
        }
        self.maint.typed.clear();
        self.maint.typing = false;
        self.maint.plan_error = None;
        self.maint.pg_recorded = self.root.join(PG_RECORD.trim_start_matches('/')).exists();
        self.maint.pg_installed = self.root.join("usr/bin/postgres").exists();
        self.maint.plan = match self
            .host
            .setup_plan()
            .map_err(|e| e.to_string())
            .and_then(|text| toml::from_str::<Plan>(&text).map_err(|e| e.to_string()))
        {
            Ok(plan) => Some(plan),
            Err(error) => {
                self.maint.plan_error = Some(format!("The plan cannot be read: {error}"));
                None
            }
        };
    }

    /// After a successful uninstall nothing is left to go to: the tool
    /// removed itself, so no key may reach the helper.
    pub(in crate::tui) fn gone(&self) -> bool {
        uninstall_run(self).is_some_and(Run::ok)
    }

    fn typed_key(&mut self, key: Key) {
        match key {
            Key::Char(c) if self.maint.typed.chars().count() < 255 => self.maint.typed.push(c),
            Key::Backspace => {
                self.maint.typed.pop();
            }
            Key::ClearLine => self.maint.typed.clear(),
            Key::Enter => self.maint.typing = false,
            Key::Esc => {
                self.maint.typing = false;
                self.maint.typed = std::mem::take(&mut self.maint.typed_before);
            }
            _ => {}
        }
    }

    pub(super) fn uninstall_key(&mut self, key: Key) {
        if self.maint.folder.editing() {
            return self.folder_key(key);
        }
        if self.maint.typing {
            return self.typed_key(key);
        }
        if let Some(run) = uninstall_run(self) {
            if !run.running() && !run.ok() && key == Key::Enter {
                let (work, at) = (run.work.clone(), run.stopped_at().unwrap_or(0));
                self.begin(work, at);
            }
            return;
        }
        let shown = choices(self);
        if self.move_row(&key, shown.len()) {
            return;
        }
        match (shown.get(self.nav.row), &key) {
            // Enter selects and moves on; only Uninstall asks (no stray Enters).
            (Some(Choice::Keep), Key::Char(' ') | Key::Enter) => {
                self.maint.everything = false;
                if key == Key::Enter {
                    self.nav.row = choices(self).len() - 1;
                }
            }
            (Some(Choice::Everything), Key::Char(' ') | Key::Enter) => {
                self.maint.everything = true;
                if key == Key::Enter {
                    self.nav.row += 2 + usize::from(self.maint.first);
                }
            }
            (Some(Choice::First), Key::Char(' ') | Key::Enter) => {
                self.maint.first = !self.maint.first;
            }
            (Some(Choice::Folder), Key::Enter) => self.maint.folder.edit(),
            (Some(Choice::Confirm), Key::Enter) => {
                self.maint.typed_before = self.maint.typed.clone();
                self.maint.typing = true;
            }
            (Some(Choice::Go), Key::Enter) => self.ask_uninstall(),
            _ => {}
        }
    }

    fn ask_uninstall(&mut self) {
        let Some(plan) = &self.maint.plan else {
            let why = self.maint.plan_error.clone().unwrap_or_default();
            self.outcome = Some((false, why));
            return;
        };
        let choices = choices(self);
        if self.maint.everything && self.maint.typed != plan.hostname {
            self.outcome = Some((
                false,
                format!("Type {} to confirm Remove everything", plan.hostname),
            ));
            self.nav.row = choices
                .iter()
                .position(|c| *c == Choice::Confirm)
                .unwrap_or(0);
            return;
        }
        if self.maint.first {
            self.poll_folder(std::time::Instant::now());
            let removed = self
                .maint
                .everything
                .then(|| {
                    crate::setup::remove::removed_by_everything(std::path::Path::new(
                        &self.maint.folder.text,
                    ))
                })
                .flatten();
            let why = if let Some(folder) = removed {
                Some(format!(
                    "Remove everything removes {folder}: choose another folder"
                ))
            } else if self.maint.folder.pending() {
                Some("Wait: the folder is still being checked".into())
            } else if !self.maint.folder.ok() {
                Some("Choose a folder for the backup first".into())
            } else {
                None
            };
            if let Some(why) = why {
                self.outcome = Some((false, why));
                self.nav.row = choices
                    .iter()
                    .position(|c| *c == Choice::Folder)
                    .unwrap_or(0);
                return;
            }
        }
        let (text, detail) = match (self.maint.everything, self.maint.first) {
            (true, true) => ("Remove OpenVIBES and all its data?", "backup first"),
            (true, false) => ("Remove OpenVIBES and all its data?", "no backup"),
            (false, _) => ("Remove OpenVIBES?", "the data stays"),
        };
        self.question = Some((
            Question::Maint {
                text: text.into(),
                detail: detail.into(),
                then: Then::Uninstall,
            },
            false, // starts on No: a stray Enter removes nothing (user, 2026-10-12)
        ));
    }

    pub(super) fn uninstall_yes(&mut self) {
        let Some(plan) = self.maint.plan.clone() else {
            return;
        };
        let file = self.maint.first.then(|| self.backup_file());
        self.begin(work(&plan, self.maint.everything, file.as_deref()), 0);
    }
}
