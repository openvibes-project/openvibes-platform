//! Maintenance › Uninstall (spec §6; maint4.py, backupdefault.py): Keep
//! the data (default) or Remove everything (type the host name, ✓ when it
//! matches; nothing is left behind); Back up first as in Update; the
//! standard question. The tool removes itself last, so once it is done,
//! Enter quits.

use platform_host::{Host, RemoveStep, StepState};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Then, failure, folder};
use crate::{
    setup::plan::Plan,
    tui::{
        app::{App, Key, Question},
        run::{Call, Kind, Run, Work},
        status::wrap,
        ui::{
            bar::Bar,
            frame,
            list::{self, Row},
            logo::Header,
            steps,
        },
    },
};

/// Setup's record that it installed PostgreSQL (readable by all).
const PG_RECORD: &str = "etc/openvibes/setup-installed-postgresql";

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
fn postgres(everything: bool, recorded: bool) -> &'static str {
    match (everything, recorded) {
        (false, _) => "PostgreSQL stays installed: keeping the data keeps it.",
        (true, true) => "PostgreSQL goes too if nothing else uses it: Setup installed it.",
        (true, false) => "PostgreSQL stays: Setup did not install it.",
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
            postgres(true, app.maint.pg_recorded)
        )),
        _ => dim(postgres(false, false).into()),
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
    let height = u16::try_from(rows.len() * 2 + 1)
        .unwrap_or(u16::MAX)
        .min(area.height.saturating_sub(4));
    let mut scroll = app.nav.scroll.get();
    let mut lines = list::lines(t, &rows, app.nav.row, &mut scroll, height, 26);
    app.nav.scroll.set(scroll);
    if let Some(choice) = chosen {
        lines.extend(help(app, choice));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_run<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let Kind::Uninstall { everything } = run.work.kind else {
        return;
    };
    let titles: Vec<String> = RemoveStep::ALL
        .iter()
        .map(|s| s.title().to_owned())
        .collect();
    let bar = match run.current() {
        Some(i) => Bar::Busy {
            text: format!("Step {} of {}: {}", i + 1, titles.len(), titles[i]),
            tick: app.tick_count,
        },
        None if run.ok() => Bar::only(&[("Enter", "Quit")]),
        None => Bar::act(&[("Enter", "Try again")]),
    };
    let area = frame::draw(frame, t, head, Some("Uninstalling"), &app.bar(bar));
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
            format!("    ✓ OpenVIBES is removed from this host ({})", run.took()),
            t.green(),
        ));
        let stays = if everything {
            format!(
                "Nothing is left behind. {}",
                postgres(true, app.maint.pg_recorded)
            )
        } else {
            "The data stays in /etc/openvibes and /var/lib/openvibes-* for a reinstall. \
             PostgreSQL stays installed."
                .into()
        };
        let backup = run.work.calls.first().and_then(|c| match c {
            Call::Remove(_, args) => args
                .iter()
                .position(|a| a == "--backup")
                .and_then(|i| args.get(i + 1)),
            _ => None,
        });
        let key = app
            .maint
            .plan
            .as_ref()
            .and_then(|p| p.root_key_out.as_ref())
            .filter(|_| everything);
        let mut notes = vec![stays];
        notes.extend(backup.map(|f| format!("Backup: {f}. Copy it off this host.")));
        notes.extend(key.map(|k| {
            format!(
                "If you kept the root key file {}, it belongs to the old CA: delete it.",
                k.display()
            )
        }));
        for note in notes {
            lines.extend(
                wrap(&note, 72, 2)
                    .into_iter()
                    .map(|l| Line::styled(format!("    {l}"), t.dim())),
            );
        }
    } else if let Some(at) = run.stopped_at() {
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        let todo = if at == 0 {
            "Nothing was removed."
        } else {
            "OpenVIBES is partly removed: Try again finishes it."
        };
        lines.extend(failure(t, why, todo));
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
        self.maint.everything = false;
        self.maint.typed.clear();
        self.maint.typing = false;
        self.maint.pg_recorded = self.root.join(PG_RECORD).exists();
        self.maint.plan = match self
            .host
            .setup_plan()
            .map_err(|e| e.to_string())
            .and_then(|text| toml::from_str::<Plan>(&text).map_err(|e| e.to_string()))
        {
            Ok(plan) => Some(plan),
            Err(error) => {
                self.outcome = Some((false, format!("the plan cannot be read: {error}")));
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
        let choices = choices(self);
        if self.move_row(key, choices.len()) {
            return;
        }
        match (choices.get(self.nav.row), key) {
            (Some(Choice::Keep), Key::Char(' ')) => self.maint.everything = false,
            (Some(Choice::Everything), Key::Char(' ')) => self.maint.everything = true,
            (Some(Choice::First), Key::Char(' ')) => self.maint.first = !self.maint.first,
            (Some(Choice::Folder), Key::Enter) => self.maint.folder.edit(),
            (Some(Choice::Confirm), Key::Enter) => {
                self.maint.typed_before = self.maint.typed.clone();
                self.maint.typing = true;
            }
            (Some(Choice::Keep | Choice::Everything | Choice::First | Choice::Go), Key::Enter) => {
                self.ask_uninstall();
            }
            _ => {}
        }
    }

    fn ask_uninstall(&mut self) {
        let Some(plan) = &self.maint.plan else {
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
            if !self.maint.folder.ok() {
                let why = if self.maint.folder.pending() {
                    "Wait: the folder is still being checked"
                } else {
                    "Choose a folder for the backup first"
                };
                self.outcome = Some((false, why.into()));
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
            true,
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
