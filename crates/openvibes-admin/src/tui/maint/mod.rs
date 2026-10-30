//! Maintenance (spec §6): the menu and the pages behind it, on today's
//! backend. Pages whose backend comes with a later step are not listed
//! until then.

#[cfg(test)]
mod apply_tests;
pub mod backup;
#[cfg(test)]
mod backup_tests;
mod certs;
#[cfg(test)]
mod certs_page_tests;
#[cfg(test)]
mod certs_tests;
mod console_cert;
#[cfg(test)]
mod console_cert_tests;
mod database;
pub mod folder;
mod names;
mod os;
#[cfg(test)]
mod os_tests;
mod page;
mod parts;
#[cfg(test)]
mod parts_finish_tests;
mod parts_run;
#[cfg(test)]
mod parts_tests;
pub mod ports;
mod ports_rows;
mod ports_run;
#[cfg(test)]
mod ports_tests;
mod repair;
#[cfg(test)]
mod repair_tests;
mod replace;
#[cfg(test)]
mod replace_tests;
mod shell;
#[cfg(test)]
mod shell_tests;
mod signin;
#[cfg(test)]
mod signin_tests;
mod uninstall;
mod uninstall_run;
#[cfg(test)]
mod uninstall_tests;
mod update;
#[cfg(test)]
mod update_tests;

pub use page::Page;
pub(in crate::tui) use parts_run::with_progress;
pub use update::half_done as update_half_done;

use platform_host::Host;

use crate::setup::plan::{Component, Plan, lacks_ports, plan_of};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    app::{App, Key},
    nav::Screen,
    run::{Kind, Run},
    status::wrap,
    ui::{
        frame,
        list::{self, Row},
        logo::Header,
        theme::Theme,
    },
};

/// The Maintenance pages' own state.
#[derive(Debug, Default)]
pub struct Maint {
    /// What the helper remembered; read when Back up, Update or Uninstall opens.
    pub memory: backup::Memory,
    /// Back up first (Update, Uninstall): off by default, then the last choice.
    pub first: bool,
    pub folder: folder::Folder,
    pub browse: Option<folder::Browse>,
    /// Uninstall: Remove everything instead of Keep the data.
    pub everything: bool,
    /// The host name typed to confirm Remove everything, while typing, and before.
    pub typed: String,
    pub typing: bool,
    pub typed_before: String,
    /// `setup.toml`, read when Uninstall opens.
    pub plan: Option<crate::setup::plan::Plan>,
    /// Setup recorded installing PostgreSQL (read when Uninstall opens).
    pub pg_recorded: bool,
    /// The server package is still installed (its `/usr/bin/postgres` is there).
    pub pg_installed: bool,
    /// Why `plan` could not be read; the page says so until it reopens.
    pub plan_error: Option<String>,
    /// Optional parts: the ticks, from the plan read when the page opens.
    pub parts: parts::Parts,
    /// Ports and addresses: the saved plan, the edits, the port being typed.
    pub ports: ports::Ports,
    /// Certificates: the report, read when the page opens.
    pub certs: certs::Certs,
    /// Names: the saved plan, the edits, the name being typed.
    pub names: names::Names,
    /// Replace the intermediate: the root key file picked (Quick).
    pub replace: replace::Replace,
    /// Console sign-in: the new password, shown once; dropped on leaving.
    pub signin: Option<signin::Shown>,
    /// Operating system: the distribution and last check, read when the page opens.
    pub os: Option<platform_host::os_updates::OsInfo>,
}

impl Maint {
    /// A value is being typed on a page: its keys are the page's.
    pub fn editing(&self) -> bool {
        self.folder.editing()
            || self.typing
            || self.ports.typing()
            || self.names.typing()
            || self.replace.picking()
    }
}

/// What Yes to a Maintenance question does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Then {
    Update,
    Uninstall,
    Parts,
    Ports,
    Names,
    OsUpdate,
    OsRestart,
    Replace,
    ConsoleCertSet,
    ConsoleCertReset,
    SignIn,
    Shell,
}

#[derive(Clone, Copy)]
enum Entry {
    Page(Page),
    /// Asked on the menu: no page (shell.py).
    Shell,
}

/// The menu, in spec §3's order; later tasks add their pages.
const ENTRIES: [(Entry, &str); 11] = [
    (Entry::Page(Page::Update), "Update OpenVIBES"),
    (Entry::Page(Page::Os), "Operating system"),
    (Entry::Page(Page::Repair), "Repair"),
    (Entry::Page(Page::Parts), "Optional parts"),
    (Entry::Page(Page::Ports), "Ports and addresses"),
    (Entry::Page(Page::Certificates), "Certificates"),
    (Entry::Page(Page::Database), "Database"),
    (Entry::Page(Page::SignIn), "Console sign-in"),
    (Entry::Page(Page::Backup), "Back up"),
    (Entry::Shell, "Shell"),
    (Entry::Page(Page::Uninstall), "Uninstall"),
];

fn value<H: Host>(app: &App<H>, entry: Entry) -> String {
    match entry {
        Entry::Shell => "the operating system's command line, for experts".into(),
        Entry::Page(Page::Update) => match &app.update {
            Some(v) => format!("{v} is available"),
            None if update::updates_available(&app.packages) => "updates are available".into(),
            None => "up to date".into(),
        },
        Entry::Page(Page::Os) => os::summary(&app.host),
        Entry::Page(Page::Repair) => "check every step, fix what is wrong".into(),
        Entry::Page(Page::Parts) => plan_of_host(app).map_or_else(
            || "cannot be read".into(),
            |plan| {
                let parts: Vec<&str> = [
                    (Component::Agent, "agent on this host"),
                    (Component::Assistant, "assistant"),
                ]
                .iter()
                .filter(|(c, _)| plan.has(*c))
                .map(|(_, n)| *n)
                .collect();
                if parts.is_empty() {
                    "none".into()
                } else {
                    parts.join(" · ")
                }
            },
        ),
        Entry::Page(Page::Ports) => plan_of_host(app).map_or_else(
            || "cannot be read".into(),
            |p| {
                format!(
                    "console {}, agents {} and {}, devices 514",
                    p.console_port, p.ingest_port, p.distribution_port
                )
            },
        ),
        Entry::Page(Page::Certificates) => certs::summary(&app.host),
        Entry::Page(Page::Database) => "schema, size, automatic clean-up".into(),
        Entry::Page(Page::SignIn) => "reset the admin password".into(),
        Entry::Page(Page::Backup) => "save the database to a folder you choose".into(),
        Entry::Page(Page::Uninstall) => "remove OpenVIBES from this host".into(),
        Entry::Page(
            Page::Names
            | Page::Replace
            | Page::Console
            | Page::ConsoleUse
            | Page::Folder
            | Page::WhatsNew,
        ) => String::new(),
    }
}

/// The saved plan, for the menu's values; `None` when it cannot be read.
fn plan_of_host<H: Host>(app: &App<H>) -> Option<Plan> {
    plan_of(&app.host.setup_plan().ok()?).ok()
}

/// The menu's names, in order (tests).
#[cfg(test)]
pub fn names() -> Vec<&'static str> {
    ENTRIES.iter().map(|(_, n)| *n).collect()
}

/// The menu row of `name`.
pub fn row_of(name: &str) -> usize {
    ENTRIES
        .iter()
        .position(|(_, n)| *n == name)
        .expect("a Maintenance entry")
}

/// The saved plan for a page that changes it. A plan from before the
/// port choices is refused: its real ports are in root-only files, and
/// a default would move a working service (Repair saves them, #76).
pub(super) fn read_plan<H: Host>(host: &H) -> Result<Plan, String> {
    let unread = |e: String| format!("The plan cannot be read: {e}");
    let text = host.setup_plan().map_err(|e| unread(e.to_string()))?;
    if lacks_ports(&text) {
        return Err("Run Repair first: this plan is from an older version.".into());
    }
    plan_of(&text).map_err(unread)
}

/// Other work running, or a half-done update or uninstall (Repair's words).
pub(super) fn busy<H: Host>(app: &App<H>) -> Option<String> {
    if app.run.as_ref().is_some_and(Run::running) {
        return Some("Wait: other work is still running".into());
    }
    let (what, todo) = repair::half_note(app.half_done.as_deref()?);
    Some(format!("{what}{todo}"))
}

/// Why a page's Apply must not ask now: other work running, a half-done
/// update or uninstall (Repair's words), or a plan that is not the one
/// the page opened with. `None` when it may ask.
pub(super) fn cannot_ask<H: Host>(app: &App<H>, opened: Option<&Plan>) -> Option<String> {
    if let Some(why) = busy(app) {
        return Some(why);
    }
    match read_plan(&app.host) {
        Ok(plan) if Some(&plan) == opened => None,
        Ok(_) => Some("The setup changed meanwhile: open the page again.".into()),
        Err(why) => Some(why),
    }
}

/// "3.1 GB", "42 MB", "1 KB".
pub fn human(bytes: u64) -> String {
    let mb = bytes as f64 / (1024.0 * 1024.0);
    if mb >= 1024.0 {
        format!("{:.1} GB", mb / 1024.0)
    } else if mb >= 1.0 {
        format!("{mb:.0} MB")
    } else {
        format!("{} KB", bytes.div_ceil(1024))
    }
}

/// An information row in the pages' value column (26 wide, maint3.py).
pub fn info(name: &str, value: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![Span::raw(format!("    {name:<26} "))];
    spans.extend(value);
    Line::from(spans)
}

/// A failed step (spec §2 "Errors"): what failed and why in red, what to
/// do and what was left as it was, dim.
pub fn failure(theme: &Theme, why: &str, todo: &str) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = wrap(why, 72, 2)
        .into_iter()
        .map(|l| Line::styled(format!("    {l}"), theme.red()))
        .collect();
    out.extend(
        wrap(todo, 72, 2)
            .into_iter()
            .map(|l| Line::styled(format!("    {l}"), theme.dim())),
    );
    out
}

pub fn draw_menu<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let bar = app.bar(shell::menu_bar(
        app,
        matches!(ENTRIES[app.nav.row].0, Entry::Shell),
    ));
    let area = frame::draw(frame, &app.theme, head, Some("Maintenance"), &bar);
    let rows: Vec<Row> = ENTRIES
        .iter()
        .map(|(e, name)| Row::entry(name, &value(app, *e)))
        .collect();
    let mut scroll = app.nav.scroll.get();
    let lines = list::lines(&app.theme, &rows, app.nav.row, &mut scroll, area.height, 22);
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, page: Page) {
    match page {
        Page::Database => database::draw(frame, head, app),
        Page::SignIn => signin::draw(frame, head, app),
        Page::Backup => backup::draw(frame, head, app),
        Page::Update => update::draw(frame, head, app),
        Page::Os => os::draw(frame, head, app),
        Page::Repair => repair::draw(frame, head, app),
        Page::Parts => parts::draw(frame, head, app),
        Page::Ports => ports::draw(frame, head, app),
        Page::Certificates => certs::draw(frame, head, app),
        Page::Names => names::draw(frame, head, app),
        Page::Replace => replace::draw(frame, head, app),
        Page::Console => console_cert::draw(frame, head, app),
        Page::ConsoleUse => console_cert::draw_use(frame, head, app),
        Page::Uninstall => uninstall::draw(frame, head, app),
        Page::WhatsNew => update::draw_whats_new(frame, head, app),
        Page::Folder => folder::draw(frame, head, app),
    }
}

impl<H: Host> App<H> {
    pub(super) fn menu_key(&mut self, key: Key) {
        if self.move_row(&key, ENTRIES.len()) || key != Key::Enter {
            return;
        }
        match ENTRIES[self.nav.row].0 {
            Entry::Page(page) => self.open_page(page),
            Entry::Shell => self.ask_shell(),
        }
    }

    pub(super) fn open_page(&mut self, page: Page) {
        self.message = None;
        self.nav.go(Screen::Maint(page));
        match page {
            Page::Database => {
                self.read(database::work());
            }
            Page::Backup => {
                // A finished backup's result is not news the next time.
                if self
                    .run
                    .as_ref()
                    .is_some_and(|r| !r.running() && matches!(r.work.kind, Kind::Backup { .. }))
                {
                    self.run = None;
                }
                self.load_backup_choice();
            }
            Page::Update => {
                // A finished update's result is not news the next time.
                if self
                    .run
                    .as_ref()
                    .is_some_and(|r| !r.running() && matches!(r.work.kind, Kind::Update { .. }))
                {
                    self.run = None;
                }
                self.load_backup_choice();
            }
            Page::Os => self.open_os(),
            Page::SignIn => self.open_signin(),
            Page::Repair => self.open_repair(),
            Page::Parts => self.open_parts(),
            Page::Ports => self.open_ports(),
            Page::Certificates => self.open_certificates(),
            Page::Names => self.open_names(),
            Page::Replace => self.open_replace(),
            Page::Console => self.nav.row = 0,
            Page::ConsoleUse => self.open_console_use(),
            Page::Uninstall => self.open_uninstall(),
            Page::WhatsNew | Page::Folder => {}
        }
    }

    pub(super) fn maint_key(&mut self, page: Page, key: Key) {
        match page {
            // A report: it has no keys of its own.
            Page::Database => {}
            Page::SignIn => self.signin_key(key),
            Page::Backup => self.backup_key(key),
            Page::Update => self.update_key(key),
            Page::Os => self.os_key(key),
            Page::Repair => self.repair_key(key),
            Page::Parts => self.parts_key(key),
            Page::Ports => self.ports_key(key),
            Page::Certificates => self.certificates_key(key),
            Page::Names => self.names_key(key),
            Page::Replace => self.replace_key(key),
            Page::Console => self.console_key(key),
            Page::ConsoleUse => self.console_use_key(key),
            Page::Uninstall => self.uninstall_key(key),
            Page::WhatsNew => {}
            Page::Folder => self.browse_key(key),
        }
    }
}

impl<H: Host> App<H> {
    pub(super) fn maint_yes(&mut self, then: Then) {
        match then {
            Then::Update => self.update_yes(),
            Then::Uninstall => self.uninstall_yes(),
            Then::OsUpdate => self.os_update_yes(),
            Then::OsRestart => self.os_restart_yes(),
            Then::Parts => self.parts_yes(),
            Then::Ports => self.ports_yes(),
            Then::Names => self.names_yes(),
            Then::Replace => self.replace_yes(),
            Then::ConsoleCertSet => self.console_set_yes(),
            Then::ConsoleCertReset => self.console_reset_yes(),
            Then::SignIn => self.signin_yes(),
            Then::Shell => self.shell_yes(),
        }
    }

    /// A run ended: the files it changes are read again.
    pub(super) fn run_ended(&mut self, background: bool) {
        self.files_changed();
        // The tool is gone: show the result, whatever screen this was on.
        if self.gone() && self.nav.screen != Screen::Maint(Page::Uninstall) {
            self.nav.go(Screen::Maint(Page::Uninstall));
        }
        if !background {
            self.signin_ended();
            self.names_ended();
            self.parts_ended();
            self.repair_ended();
            self.install_ended();
            self.replace_ended();
            self.console_cert_ended();
            self.os_ended();
        }
    }
}

/// Status's problem for a half-done job (decision 17).
pub fn half_done_problem(kind: Option<&str>) -> Option<super::status::Item> {
    let (text, page) = match kind? {
        "update" => (
            "An update stopped half way: the services may be stopped",
            Page::Update,
        ),
        "uninstall" => ("An uninstall stopped half way", Page::Uninstall),
        _ => return None,
    };
    Some(super::status::Item::Problem {
        text: text.into(),
        fix: Some(super::status::Fix::Finish(page)),
        red: false,
        help: None,
    })
}
