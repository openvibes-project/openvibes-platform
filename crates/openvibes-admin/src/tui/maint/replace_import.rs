//! Replace for an imported intermediate (certs4b.py #11): the install's
//! Certificate and Private key rows and screens, then Replace. Enter on
//! Replace sends both to `ca-import`, which refuses a root other than the
//! one agents trust; once it kept them, 4a's question, then `ca-replace`.

use platform_host::{Host, Service};

use super::Page;
use crate::tui::{
    app::{App, Key},
    install::{Stage, Which},
    nav::Screen,
    run::{Call, Kind},
    ui::list::Row,
};

/// Said once `ca-import` kept the next one.
const SAME_ROOT: &str = "Under the same root: agents keep working.";

/// The page's note, rows, Enter and the line under them.
type Layout<'a> = (
    &'static str,
    Vec<Row>,
    Option<&'static str>,
    Option<Result<&'a str, &'a str>>,
);

pub(super) fn page<H: Host>(app: &App<H>) -> Layout<'_> {
    let install = &app.install;
    let ready = install.both_added();
    let mut rows = install.import_rows(&app.theme);
    let days = format!("agents move over in {} days", app.maint.replace.days);
    rows.push(Row::entry("Replace", &days));
    let enter = match app.nav.row {
        0 => Some("Open"),
        1 if install.imported.is_some() => Some("Open"),
        2 if ready => Some("Replace"),
        _ => None,
    };
    let said = match (&install.error, &app.maint.replace.root) {
        (Some(why), _) => Some(Err(why.as_str())),
        (None, Some(Err(why))) => Some(Err(why.as_str())),
        _ if install.import_done.is_some() => Some(Ok(SAME_ROOT)),
        _ => None,
    };
    let note = "The same screens as at install. Nothing changes until Replace.";
    (note, rows, enter, said)
}

impl<H: Host> App<H> {
    /// Nothing added yet; how long agents take to move over.
    pub(super) fn open_import(&mut self) {
        self.install.forget_import();
        self.install.error = None;
        self.install.pick = None;
        self.maint.replace.days = self
            .host
            .read_config(Service::Ingest)
            .ok()
            .and_then(|text| text.parse::<toml::Table>().ok())
            .and_then(|table| table.get("client_certificate_days")?.as_integer())
            .unwrap_or(30);
        self.nav.row = 0;
    }

    pub(super) fn import_key(&mut self, key: Key) {
        if self.move_row(&key, 3) || key != Key::Enter {
            return;
        }
        let install = &mut self.install;
        match self.nav.row {
            0 => self.nav.go(Screen::Install(Stage::Add(Which::Cert))),
            1 if install.imported.is_some() => self.nav.go(Screen::Install(Stage::Add(Which::Key))),
            2 if install.import_done.is_some() => return self.ask_replace(),
            2 if install.both_added() => return self.send_import(),
            _ => return,
        }
        self.install.error = None;
    }

    /// `ca-import` ended on this page (true): kept, the question; refused,
    /// the red line `import_ended` set.
    pub(super) fn import_ended_here(&mut self) -> bool {
        let imported = self.run.as_ref().is_some_and(|run| {
            matches!(run.work.kind, Kind::Ca { .. })
                && matches!(run.work.calls.first(), Some(Call::CaImport(_)))
        });
        if !imported || self.nav.screen != Screen::Maint(Page::Replace) {
            return false;
        }
        if self.install.import_done.is_some() {
            self.nav.row = 2;
            self.ask_replace();
        }
        true
    }

    /// Replace was left: the import is forgotten.
    pub(in crate::tui) fn replace_left(&mut self) {
        if self.maint.certs.imported() {
            self.install.forget_import();
        }
    }
}

#[cfg(test)]
#[path = "replace_import_tests.rs"]
mod tests;
