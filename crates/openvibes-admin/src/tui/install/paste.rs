//! The paste box (ca2.py `paste`) and "From a file on this host": a
//! certificate pasted, typed line by line or read from a file, checked
//! at once in-process (the same checks the helper runs again).
//!
//! A bracketed paste arrives whole (`Key::Paste`). A terminal without it
//! sends the lines as keys: Enter adds a new line until an `-----END`
//! line is there; after that Enter is "Use it", once the check passed.

use platform_host::Host;
use platform_pki::PkiError;
use ratatui::{Frame, text::Line, widgets::Paragraph};

use super::{Install, Which, import};
use crate::{
    setup::request::message,
    tui::{
        app::{App, Key},
        ca_request::{self, MAX, Picked, pick},
        ui::{bar::Bar, frame, logo::Header},
    },
};

/// The box's inside: 68 columns, 4 lines.
const WIDE: usize = 68;
const TALL: usize = 4;

impl Install {
    /// The check of `text` as `which`: the lines that say it is right, or
    /// why it is not; `None` while the box is empty.
    pub(super) fn check(&self, which: Which, text: &str) -> Option<Result<Vec<String>, String>> {
        if text.trim().is_empty() {
            return None;
        }
        let now = chrono::Utc::now();
        Some(match which {
            Which::Cert | Which::Key => return self.import_check(which, text),
            Which::Signed => match self.csr() {
                None => Err("There is no request here: make one first.".into()),
                Some(csr) => platform_pki::check_signed_request(csr, text, now)
                    .map(|s| {
                        vec![
                            format!(
                                "Intermediate for {} · signed by {}",
                                self.hostname.trim(),
                                s.issuer
                            ),
                            format!("Matches the request · valid until {}", s.not_after),
                        ]
                    })
                    .map_err(|e| message(&e)),
            },
            // Before the signed certificate is added, the root is checked
            // against itself (a self-signed CA signs itself); the helper
            // checks it against the certificate once both are added.
            Which::Root => {
                let cert = self.cert.as_ref().map_or(text, |c| c.0.as_str());
                platform_pki::check_root_signed(text, cert, now)
                    .map(|name| {
                        let mut said = vec![format!("{name} · a root CA (self-signed)")];
                        if self.cert.is_some() {
                            said.push("Signed the intermediate directly".into());
                        }
                        said
                    })
                    .map_err(|e| match e {
                        PkiError::Several(n) => format!(
                            "That is {n} certificates: paste only your root CA's certificate."
                        ),
                        e => message(&e),
                    })
            }
        })
    }
}

const PASTE_HELP: &str = "Paste the whole block, BEGIN to END lines included.";
const FILE_HELP: &str = "The file's text, checked below.";

/// A PEM private key block is in `text` (`BEGIN PRIVATE KEY`, `BEGIN EC
/// PRIVATE KEY`…).
pub(super) fn holds_private_key(text: &str) -> bool {
    text.lines().any(|l| {
        let l = l.trim();
        l.starts_with("-----BEGIN ") && l.ends_with("PRIVATE KEY-----")
    })
}

/// An `-----END` line is there: Enter is "Use it" from now on.
pub(super) fn ended(text: &str) -> bool {
    text.lines().any(|l| l.trim_start().starts_with("-----END"))
}

pub(super) fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, which: Which) {
    let t = &app.theme;
    let install = &app.install;
    let text = install.paste.as_deref().unwrap_or_default();
    let check = install.check(which, text);
    let bar = if matches!(check, Some(Ok(_))) && ended(text) {
        Bar::edit("", "", &[("Enter", "Use it")])
    } else {
        Bar::edit("", "", &[])
    };
    let (title, help) = match (which, &install.paste_file) {
        (Which::Signed, None) => ("Paste the signed certificate".to_owned(), PASTE_HELP),
        (Which::Root, None) => ("Paste your CA's certificate".to_owned(), PASTE_HELP),
        (Which::Cert, None) => ("Paste the certificate".to_owned(), import::PASTE_NOTE),
        (Which::Key, None) => ("Paste the private key".to_owned(), import::KEY_NOTE),
        (Which::Signed, Some(file)) => (format!("The signed certificate, from {file}"), FILE_HELP),
        (Which::Root, Some(file)) => (format!("Your CA's certificate, from {file}"), FILE_HELP),
        (Which::Cert, Some(file)) => (format!("The certificate, from {file}"), FILE_HELP),
        (Which::Key, Some(file)) => (format!("The private key, from {file}"), FILE_HELP),
    };
    let bar = install.secret_bar().unwrap_or(bar);
    let area = frame::draw(frame, t, head, Some(&title), &app.bar(bar));
    let mut lines = vec![
        Line::raw(""),
        Line::styled(format!("    {help}"), t.dim()),
        Line::raw(""),
        Line::styled(format!("  ┌{}┐", "─".repeat(WIDE + 2)), t.dim()),
    ];
    // The cursor sits after the last character, on a line of its own
    // after a new line.
    let mut typed: Vec<String> = text.split('\n').map(str::to_owned).collect();
    // Folded, a pasted block's last new line is not shown: the cursor
    // stays on its END line (ca2.py).
    if typed.len() > TALL && typed.last().is_some_and(String::is_empty) {
        typed.pop();
    }
    let mut shown: Vec<String> = if typed.len() > TALL {
        vec![
            typed[0].clone(),
            typed[1].clone(),
            "…".into(),
            typed[typed.len() - 1].clone(),
        ]
    } else {
        typed
    };
    if let Some(last) = shown.last_mut() {
        last.push('█');
    }
    for line in shown {
        let cut: String = line.chars().take(WIDE).collect();
        let pad = WIDE - cut.chars().count();
        lines.push(Line::from(vec![
            ratatui::text::Span::styled("  │", t.dim()),
            ratatui::text::Span::raw(format!(" {cut}{} ", " ".repeat(pad))),
            ratatui::text::Span::styled("│", t.dim()),
        ]));
    }
    lines.push(Line::styled(
        format!("  └{}┘", "─".repeat(WIDE + 2)),
        t.dim(),
    ));
    lines.push(Line::raw(""));
    let ok = |s: String| {
        Line::from(vec![
            ratatui::text::Span::styled("    ✓", t.green()),
            ratatui::text::Span::raw(format!(" {s}")),
        ])
    };
    match check {
        Some(Ok(said)) => lines.extend(said.into_iter().map(ok)),
        Some(Err(why)) => lines.extend(
            // A chain with a gap: ours is fine, the line says what is missing.
            (install.import_partial(which, text).map(ok).into_iter()).chain(
                crate::tui::status::wrap(&format!("✗ {why}"), 72, 2)
                    .into_iter()
                    .map(|l| Line::styled(format!("    {l}"), t.red())),
            ),
        ),
        None => {}
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// The paste box's keys.
    pub(super) fn paste_key(&mut self, which: Which, key: Key) {
        let Some(text) = self.install.paste.as_mut() else {
            return;
        };
        match key {
            Key::Paste(pasted) => {
                let pasted = pasted.replace("\r\n", "\n").replace('\r', "\n");
                let room = MAX.saturating_sub(text.len());
                text.extend(pasted.chars().scan(0, |n, c| {
                    *n += c.len_utf8();
                    (*n <= room).then_some(c)
                }));
            }
            Key::Char(c) if !c.is_control() && text.len() < MAX => text.push(c),
            Key::Backspace => {
                text.pop();
            }
            Key::ClearLine => text.clear(),
            Key::Enter if !ended(text) => text.push('\n'),
            Key::Enter => {
                let mut text = text.clone();
                if let Some(Ok(_)) = self.install.check(which, &text) {
                    return self.use_it(which, text);
                }
                // It may be a key.
                zeroize::Zeroize::zeroize(&mut text);
            }
            Key::Esc => {
                self.install.close_box();
                self.nav.row = 0;
            }
            _ => {}
        }
        if which == Which::Key {
            self.ask_if_locked();
        }
    }

    /// The certificate is added; with both, the helper keeps them.
    fn use_it(&mut self, which: Which, mut text: String) {
        if let Which::Cert | Which::Key = which {
            self.import_use(which, &text);
            return zeroize::Zeroize::zeroize(&mut text);
        }
        let pem = text.trim().to_owned();
        let now = chrono::Utc::now();
        match which {
            Which::Cert | Which::Key => return,
            Which::Signed => {
                let Some(csr) = self.install.csr() else {
                    return;
                };
                let Ok(signed) = platform_pki::check_signed_request(csr, &pem, now) else {
                    return;
                };
                self.install.cert = Some((pem, signed.issuer));
            }
            Which::Root => {
                let Ok(name) = platform_pki::check_root_signed(&pem, &pem, now) else {
                    return;
                };
                self.install.root_pem = Some(pem);
                self.install.root_added = Some(name);
            }
        }
        self.install.paste = None;
        self.install.paste_file = None;
        self.install.error = None;
        self.nav.pop();
        self.accept_both();
    }

    /// The file browser's keys: Enter opens a folder or reads a file into
    /// the box (at most `MAX`); Esc goes back to the two ways.
    pub(super) fn pick_key(&mut self, key: Key) {
        let path = match pick(
            &mut self.install.pick,
            &mut self.nav.row,
            &self.nav.scroll,
            key,
        ) {
            Picked::Nothing => return,
            Picked::Closed => {
                self.nav.row = 1;
                return;
            }
            Picked::File(path) => path,
        };
        let read = ca_request::read(&path);
        let text = read.as_deref().unwrap_or_default();
        let refused = if holds_private_key(text) {
            Some("That file holds a private key: pick the certificate.")
        } else if !text.contains("-----BEGIN CERTIFICATE-----") {
            Some("That file holds no certificate: pick the certificate.")
        } else {
            None
        };
        match (read, refused) {
            (Err(error), _) => {
                if let Some(browse) = &mut self.install.pick {
                    browse.error = Some(format!("{}: {error}", path.display()));
                }
            }
            // A key, or anything but a certificate, never
            // reaches the box, nor stays here.
            (Ok(_), Some(why)) => {
                if let Some(browse) = &mut self.install.pick {
                    browse.refused = Some(why.into());
                }
            }
            (Ok(text), None) => {
                self.install.paste = Some(text);
                self.install.paste_file = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned());
                self.install.pick = None;
            }
        }
    }
}
