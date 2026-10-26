//! Replace for an imported intermediate (certs4b.py #11): the install's
//! Certificate and Private key rows and screens, then Replace. Both added,
//! the chain is checked here against this host's root and the intermediate
//! in use; Enter on Replace asks 4a's question, and only Yes sends them:
//! `ca-import` then `ca-replace`, one run under one password. No and Esc
//! stage nothing. The helper checks everything again.

use platform_host::{Host, Service};

use crate::{
    setup::import::{IN_USE, another_root},
    tui::{
        app::{App, Key},
        install::{Added, Stage, Which},
        nav::Screen,
        run::{Call, Kind, Work},
        ui::list::Row,
    },
};

/// Said once both are added and the root is this host's.
const SAME_ROOT: &str = "Under the same root: agents keep working.";
const INTERMEDIATE: &str = "/etc/openvibes/pki/intermediate.crt";

/// Both added: the chain's root is this host's (as DER) and ours is not
/// the intermediate in use; `None` before.
fn checked<H: Host>(app: &App<H>) -> Option<Result<(), String>> {
    let imported = app.install.imported.as_ref().filter(|i| i.key.is_some())?;
    let Added::Chain(chain) = &imported.cert else {
        return None;
    };
    let Some(Ok((root, _))) = &app.maint.replace.root else {
        return None;
    };
    let first = |pem: &str| platform_pki::certificates(pem).ok()?.into_iter().next();
    if platform_pki::certificates(&chain.root).ok() != platform_pki::certificates(root).ok() {
        return Some(Err(another_root(&chain.root, root)));
    }
    let in_use = app.maint.replace.in_use.as_deref().and_then(first);
    if in_use.is_some() && in_use == first(&chain.ours) {
        return Some(Err(IN_USE.into()));
    }
    Some(Ok(()))
}

/// The page's note, rows, Enter and the line under them.
pub(super) type Layout = (
    &'static str,
    Vec<Row>,
    Option<&'static str>,
    Option<Result<String, String>>,
);

pub(super) fn page<H: Host>(app: &App<H>) -> Layout {
    let install = &app.install;
    let check = checked(app);
    let ready = matches!(check, Some(Ok(())));
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
        (Some(why), _) => Some(Err(why.clone())),
        (None, Some(Err(why))) => Some(Err(why.clone())),
        _ => match check {
            Some(Ok(())) => Some(Ok(SAME_ROOT.to_owned())),
            Some(Err(why)) => Some(Err(why)),
            None => None,
        },
    };
    let note = "The same screens as at install. Nothing changes until Replace.";
    (note, rows, enter, said)
}

impl<H: Host> App<H> {
    /// Nothing added yet; how long agents take to move over.
    pub(super) fn open_import(&mut self) {
        let in_use = self.host.certificates().into_iter();
        self.maint.replace.in_use = in_use
            .filter(|(path, _)| *path == INTERMEDIATE)
            .find_map(|(_, pem)| pem.ok());
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
        match self.nav.row {
            0 => self.nav.go(Screen::Install(Stage::Add(Which::Cert))),
            1 if self.install.imported.is_some() => {
                self.nav.go(Screen::Install(Stage::Add(Which::Key)))
            }
            2 if matches!(checked(self), Some(Ok(()))) => return self.ask_replace(),
            _ => return,
        }
        self.install.error = None;
    }

    /// Yes: the import and the replacement, one run, one password.
    pub(super) fn import_yes(&mut self) {
        let Some(import) = self.install.import_call() else {
            return;
        };
        let done = "Replaced".to_owned();
        let calls = vec![import, Call::CaReplace(None)];
        self.begin(Work::new(Kind::Replace { done }, calls), 0);
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
