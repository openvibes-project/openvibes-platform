//! Maintenance (spec §6): the menu and the pages behind it, on today's
//! backend. Pages whose backend comes with a later step are not listed
//! until then; today's Components and ports and Settings files screens
//! stay behind the menu until their pages replace them.

pub mod backup;
#[cfg(test)]
mod backup_tests;
mod database;
pub mod folder;
mod parts;
#[cfg(test)]
mod parts_tests;
mod repair;
#[cfg(test)]
mod repair_tests;
mod uninstall;
#[cfg(test)]
mod uninstall_tests;
mod update;
#[cfg(test)]
mod update_tests;

pub use update::half_done as update_half_done;

use platform_host::Host;
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    app::{App, Key, Tab},
    nav::Screen,
    run::Kind,
    status::wrap,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
        theme::Theme,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Page {
    Database,
    Backup,
    Update,
    Repair,
    Parts,
    Uninstall,
    WhatsNew,
    /// The folder browser, reached with Tab from a typed folder.
    Folder,
}

impl Page {
    pub fn title(self) -> &'static str {
        match self {
            Page::Database => "Database",
            Page::Backup => "Back up",
            Page::Update => "Update OpenVIBES",
            Page::Repair => "Repair",
            Page::Parts => "Optional parts",
            Page::Uninstall => "Uninstall",
            Page::WhatsNew => "What's new",
            Page::Folder => "Choose a folder",
        }
    }
    /// What the keys do here, for Help.
    pub fn help(self) -> &'static str {
        match self {
            Page::Database => "A report: the clean-up runs by itself every night.",
            Page::Backup => {
                "Enter on Save in folder types or browses a folder; Back up now writes a new file there."
            }
            Page::Update => {
                "Space ticks Back up first; Enter on Update now updates; What's new lists the packages."
            }
            Page::Repair => {
                "It checks every step first; Fix N problems repairs, then checks again."
            }
            Page::Parts => {
                "Space ticks the agent or the assistant; Apply installs or removes what changed."
            }
            Page::Uninstall => {
                "Space chooses Keep the data or Remove everything; Uninstall asks first."
            }
            Page::WhatsNew => "A list: every package's version and the release notes' address.",
            Page::Folder => "Enter opens a folder; Use this folder picks the one shown.",
        }
    }
}

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
}

impl Maint {
    /// A value is being typed on a page: its keys are the page's.
    pub fn editing(&self) -> bool {
        self.folder.editing() || self.typing
    }
}

/// What Yes to a Maintenance question does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Then {
    Update,
    Uninstall,
    Parts,
}

#[derive(Clone, Copy)]
enum Entry {
    Page(Page),
    Legacy(Tab),
}

/// The menu, in spec §3's order; later tasks add their pages.
const ENTRIES: [(Entry, &str); 8] = [
    (Entry::Page(Page::Update), "Update OpenVIBES"),
    (Entry::Page(Page::Repair), "Repair"),
    (Entry::Page(Page::Parts), "Optional parts"),
    (Entry::Legacy(Tab::Setup), "Components and ports"),
    (Entry::Page(Page::Database), "Database"),
    (Entry::Page(Page::Backup), "Back up"),
    (Entry::Legacy(Tab::Configuration), "Settings files"),
    (Entry::Page(Page::Uninstall), "Uninstall"),
];

fn value<H: Host>(app: &App<H>, entry: Entry) -> String {
    match entry {
        Entry::Legacy(Tab::Setup) => "agent, assistant, ports".into(),
        Entry::Legacy(Tab::Configuration) => "feeds, proxy, limits, database connection".into(),
        Entry::Page(Page::Update) => match &app.update {
            Some(v) => format!("{v} is available"),
            None if update::updates_available(&app.packages) => "updates are available".into(),
            None => "up to date".into(),
        },
        Entry::Page(Page::Repair) => "check every step, fix what is wrong".into(),
        Entry::Page(Page::Parts) => "agent on this host, assistant".into(),
        Entry::Page(Page::Database) => "schema, size, automatic clean-up".into(),
        Entry::Page(Page::Backup) => "save the database to a folder you choose".into(),
        Entry::Page(Page::Uninstall) => "remove OpenVIBES from this host".into(),
        Entry::Page(Page::Folder | Page::WhatsNew) => String::new(),
    }
}

/// The menu row of `name` (tests).
#[cfg(test)]
pub fn row_of(name: &str) -> usize {
    ENTRIES
        .iter()
        .position(|(_, n)| *n == name)
        .expect("a Maintenance entry")
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
    let bar = app.bar(Bar::keys(&[("Enter", "Open")]));
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
        Page::Backup => backup::draw(frame, head, app),
        Page::Update => update::draw(frame, head, app),
        Page::Repair => repair::draw(frame, head, app),
        Page::Parts => parts::draw(frame, head, app),
        Page::Uninstall => uninstall::draw(frame, head, app),
        Page::WhatsNew => update::draw_whats_new(frame, head, app),
        Page::Folder => folder::draw(frame, head, app),
    }
}

impl<H: Host> App<H> {
    pub(super) fn menu_key(&mut self, key: Key) {
        if self.move_row(key, ENTRIES.len()) || key != Key::Enter {
            return;
        }
        match ENTRIES[self.nav.row].0 {
            Entry::Legacy(tab) => self.open(tab),
            Entry::Page(page) => self.open_page(page),
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
            Page::Repair => self.open_repair(),
            Page::Parts => self.open_parts(),
            Page::Uninstall => self.open_uninstall(),
            Page::WhatsNew | Page::Folder => {}
        }
    }

    pub(super) fn maint_key(&mut self, page: Page, key: Key) {
        match page {
            // A report: it has no keys of its own.
            Page::Database => {}
            Page::Backup => self.backup_key(key),
            Page::Update => self.update_key(key),
            Page::Repair => self.repair_key(key),
            Page::Parts => self.parts_key(key),
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
            Then::Parts => self.parts_yes(),
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
            self.repair_ended();
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
    })
}
