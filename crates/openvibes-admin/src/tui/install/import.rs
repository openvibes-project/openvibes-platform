//! Step 3, Import from your PKI (certs4b.py): a finished intermediate and
//! its key. The chain and the key are pasted, read from a file, or both
//! come from a .p12 / .pfx opened with its password in the bar. Each is
//! checked at once here (the operator owns the files; the TUI decrypts the
//! key). Once both are added, the chain and the plain PKCS#8 key go to
//! `ca-import` on stdin, under the sudo password (Next sends them again
//! after a refusal). The helper checks everything again.
//! The decrypted key is forgotten once the helper has it, or when Import or
//! the step is left. The boxes' checks and the password bar's keys are in
//! `import_paste.rs`.

use std::path::PathBuf;

use platform_host::{Host, StepState};
use platform_pki::{Chain, KeyInfo};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};
use zeroize::{Zeroize, Zeroizing};

use super::{Install, Stage, Which};
use crate::tui::{
    app::App,
    ca_request::sentence,
    nav::Screen,
    run::{Bundle, Call, Kind, Work},
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
        theme::Theme,
    },
};

pub(super) const HELP: &str =
    "Paste or pick the certificate and its key, or a .p12 with its password.";
pub(super) const PASTE_NOTE: &str =
    "Our intermediate first, then each CA above it, ending with the root.";
pub(super) const KEY_NOTE: &str = "It stays on this host, readable by root only.";
pub(super) const KEY_FIRST: &str = "Add the certificate first: the key is checked against it.";

/// The certificate rows' indices on step 3: Certificate, Private key, Next.
pub(super) const CERT: usize = 3;
pub(super) const KEY: usize = 4;
pub(super) const NEXT: usize = 5;

/// What Import from your PKI added.
pub struct Imported {
    pub chain: Chain,
    /// The plain PKCS#8 key and what it is, until the helper has it.
    pub key: Option<(Zeroizing<String>, KeyInfo)>,
    /// The .p12 file both came from.
    pub from: Option<String>,
}

/// What "Its password" opens.
pub enum Locked {
    /// A .p12 / .pfx file and its bytes, as read.
    P12(PathBuf, Vec<u8>),
    /// The locked key's PEM text in the box.
    Key(String),
}

impl Install {
    /// Both rows are added, or the helper kept them.
    pub(in crate::tui) fn both_added(&self) -> bool {
        self.import_done.is_some() || self.imported.as_ref().is_some_and(|i| i.key.is_some())
    }

    /// The decrypted key and what the bar asks are forgotten.
    pub(in crate::tui) fn forget_key(&mut self) {
        if let Some(imported) = &mut self.imported {
            imported.key = None;
        }
        self.secret = None;
        self.locked = None;
        self.unlocked = None;
    }

    /// Everything Import added is forgotten (another choice was made).
    pub(in crate::tui) fn forget_import(&mut self) {
        self.forget_key();
        self.imported = None;
        self.import_done = None;
    }

    /// A file as the screens name it: `~/…` under the operator's home.
    pub(super) fn shown(&self, path: &std::path::Path) -> String {
        super::steps::tilde(&path.display().to_string(), self.home.as_deref())
    }

    /// The help line after a .p12 filled both rows (Replace's too).
    pub(in crate::tui) fn p12_hint(&self) -> Option<String> {
        let file = self.imported.as_ref()?.from.as_ref()?;
        Some(format!(
            "From {file}. Delete that file now: its key is kept here."
        ))
    }

    /// Closes the paste box; its text is wiped, as it may be a key.
    pub(super) fn close_box(&mut self) {
        if let Some(mut text) = self.paste.take() {
            text.zeroize();
        }
        self.paste_file = None;
        self.secret = None;
        self.locked = None;
        self.unlocked = None;
    }

    /// Step 3's Certificate and Private key rows (Replace's too).
    pub(in crate::tui) fn import_rows(&self, t: &Theme) -> Vec<Row> {
        let added = |name: &str, said: Option<String>| Row::Entry {
            name: vec![Span::raw(name.to_owned())],
            value: match said {
                Some(said) => vec![
                    Span::styled("✓ added", t.green()),
                    Span::styled(said, t.dim()),
                ],
                None => vec![Span::styled("not added yet", t.yellow())],
            },
        };
        let name = (self.imported.as_ref()).map(|i| format!(" · {}", i.chain.name));
        let key = self
            .both_added()
            .then(|| " · matches the certificate".to_owned());
        vec![added("Certificate", name), added("Private key", key)]
    }

    /// `ca-import` with the chain and the plain key on stdin, once both
    /// are added.
    pub(in crate::tui) fn import_call(&self) -> Option<Call> {
        let Some(Imported {
            chain,
            key: Some((key, _)),
            ..
        }) = &self.imported
        else {
            return None;
        };
        // Ours, the CAs above it, the root, then the one key.
        let mut bundle = Zeroizing::new(String::new());
        let certs = std::iter::once(&chain.ours)
            .chain(&chain.middle)
            .chain([&chain.root]);
        for pem in certs.chain([&**key]) {
            bundle.push_str(pem.trim_end());
            bundle.push('\n');
        }
        Some(Call::CaImport(Bundle(bundle)))
    }

    /// The help line on step 3's rows 3 to 5.
    pub(super) fn import_help(&self, row: usize) -> String {
        if let Some(hint) = self.p12_hint() {
            return hint;
        }
        match &self.imported {
            None if row == KEY => KEY_FIRST.into(),
            _ if row == NEXT => "Go on to the ports.".into(),
            _ => HELP.into(),
        }
    }

    /// The bar on step 3's rows 3 to 5.
    pub(super) fn import_bar(&self, row: usize) -> Bar {
        match row {
            CERT => Bar::keys(&[("Enter", "Open")]),
            KEY if self.imported.is_some() => Bar::keys(&[("Enter", "Open")]),
            NEXT if self.both_added() => Bar::keys(&[("Enter", "Next")]),
            _ => Bar::keys(&[]),
        }
    }

    /// "Its password" in the bar, while it is asked.
    pub(super) fn secret_bar(&self) -> Option<Bar> {
        let prompt = self.secret.as_ref()?;
        Some(Bar::Typing {
            note: (prompt.failures > 0).then(|| "Wrong password.".into()),
            label: "Its password".into(),
            shown: prompt.masked(),
            done: match self.locked {
                Some(Locked::P12(..)) => "Open it",
                _ => "Unlock",
            }
            .into(),
        })
    }
}

/// Add the certificate, or the private key (certs4b.py `how`): the two
/// ways, and under them the .p12 waiting for its password, or why it was
/// refused.
pub(super) fn draw_how<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, which: Which) {
    let t = &app.theme;
    let install = &app.install;
    let (title, ways) = match which {
        Which::Cert => (
            "Add the certificate",
            [
                ("Paste it", "PEM text: ours first, then the CAs above it"),
                (
                    "From a file on this host",
                    "a .pem, or a .p12 / .pfx with the key in it",
                ),
            ],
        ),
        _ => (
            "Add the private key",
            [
                ("Paste it", "the PEM text of the key"),
                ("From a file on this host", "a .pem or .key file"),
            ],
        ),
    };
    let enter = if app.nav.row == 0 {
        "Paste it"
    } else {
        "Choose a file"
    };
    let bar = (install.secret_bar()).unwrap_or_else(|| Bar::keys(&[("Enter", enter)]));
    let area = frame::draw(frame, t, head, Some(title), &app.bar(bar));
    let rows = ways.map(|(name, value)| Row::entry(name, value));
    let mut scroll = app.nav.scroll.get();
    // The two ways and their hint lines, then the line under them.
    let room = area.height.min(5);
    let mut lines = list::lines(t, &rows, app.nav.row, &mut scroll, room, 26);
    app.nav.scroll.set(scroll);
    let failed = install.secret.as_ref().is_some_and(|s| s.failures > 0);
    match (&install.locked, &install.error) {
        (Some(Locked::P12(path, _)), _) if failed => lines.extend(
            crate::tui::status::wrap(
                &format!("✗ Wrong password for {}.", install.shown(path)),
                72,
                2,
            )
            .into_iter()
            .map(|l| Line::styled(format!("    {l}"), t.red())),
        ),
        (Some(Locked::P12(path, _)), _) => {
            let said = format!(
                "{} · a .p12 file: it is locked with a password",
                install.shown(path)
            );
            let said = crate::tui::status::wrap(&said, 70, 2);
            lines.extend(said.into_iter().enumerate().map(|(i, l)| {
                let mark = if i == 0 { "    ✓ " } else { "      " };
                Line::from(vec![Span::styled(mark, t.green()), Span::raw(l)])
            }));
        }
        (_, Some(why)) => lines.extend(
            crate::tui::status::wrap(&format!("✗ {why}"), 72, 2)
                .into_iter()
                .map(|l| Line::styled(format!("    {l}"), t.red())),
        ),
        _ => {}
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Enter on step 3's rows 3 to 5.
    pub(super) fn import_row_key(&mut self, row: usize) {
        match row {
            CERT => self.nav.go(Screen::Install(Stage::Add(Which::Cert))),
            KEY if self.install.imported.is_some() => {
                self.nav.go(Screen::Install(Stage::Add(Which::Key)))
            }
            NEXT => return self.import_next(),
            _ => return,
        }
        self.install.error = None;
    }

    /// The helper takes the import (once; again after a refusal or a
    /// cancelled password), then Next goes to the ports.
    pub(super) fn import_next(&mut self) {
        if self.install.import_done.is_some() {
            return self.next_step(2);
        }
        let Some(call) = self.install.import_call() else {
            return;
        };
        self.install.error = None;
        self.begin(Work::new(Kind::Ca { accept: true }, vec![call]), 0);
    }

    /// `ca-import` ended: `imported<TAB>…`, or why the helper refused.
    pub(super) fn import_ended(&mut self) {
        let Some(run) = &mut self.run else { return };
        // Sent or not, no copy of the key stays in the run.
        run.work.wipe();
        let install = &mut self.install;
        match &run.states[0] {
            Some(StepState::Done(out)) if out.starts_with("imported\t") => {
                install.import_done = Some(out.trim_end().to_owned());
                install.error = None;
                install.forget_key();
                if self.nav.screen == Screen::Install(Stage::Step(2)) {
                    self.nav.row = NEXT;
                }
            }
            Some(StepState::Done(out)) => {
                install.error = Some(format!("Unexpected helper output: {}", out.trim()));
            }
            Some(state) if !state.finished() => install.error = Some(sentence(state.detail())),
            _ => {}
        }
    }
}
