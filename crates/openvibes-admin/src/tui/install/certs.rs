//! Step 3, Certificates (ca.py, ca2.py, full_advanced.py): your own CA
//! (the default) or OpenVIBES makes one. With your own CA, Next makes the
//! request before anything is installed (`ca-request`); the request is
//! shown to copy, and the two certificates are added (`paste.rs`). Once
//! both are, the helper checks and keeps them (`ca-accept`): only then
//! does Next go on, as the careful CA step installs from them.

use platform_host::{Host, StepState};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    Ca, Install, Stage, Which, fields,
    steps::{Step, draw_step, name_bar, tilde, typed},
};
use crate::{
    setup::request::RequestState,
    tui::{
        app::{App, Key},
        nav::Screen,
        run::{Call, Kind, Work},
        ui::{
            bar::Bar,
            frame,
            list::{self, Row, Scroll},
            logo::Header,
        },
    },
};

const HELP: [&str; 2] = [
    "For networks with their own PKI. Your root key never comes near this host.",
    "For networks without a CA of their own.",
];
const MADE: &str = "OpenVIBES made a request; your CA signs it as an intermediate.";

impl Install {
    /// The request's PEM, whatever its state.
    pub(super) fn csr(&self) -> Option<&str> {
        match &self.request {
            Some(RequestState::Request { csr } | RequestState::Signed { csr, .. }) => Some(csr),
            None => None,
        }
    }

    /// Step 3 shows the request's rows: your own CA, once requested.
    fn requested(&self) -> bool {
        self.ca == Ca::Own && self.request.is_some()
    }

    /// The certificates added and not (yet) kept by the helper.
    fn forget_added(&mut self) {
        self.cert = None;
        self.root_pem = None;
        self.root_added = None;
    }

    /// The choice rows: the root key file only for OpenVIBES makes one.
    fn choice_rows(&self) -> usize {
        if self.ca == Ca::OpenVibes { 4 } else { 3 }
    }
}

/// What the helper's failure says, without its prefixes.
fn sentence(why: &str) -> String {
    match why.rsplit_once("openvibes-admin helper: ") {
        Some((_, said)) => said.trim().to_owned(),
        None => why
            .strip_prefix("failed: ")
            .unwrap_or(why)
            .trim()
            .to_owned(),
    }
}

/// The helper's answer: `request` or `signed<TAB>ISSUER`, then
/// `copy<TAB>PATH` when it saved a copy, then the request.
fn read_state(out: &str) -> Option<(RequestState, Option<String>)> {
    let (first, rest) = out.split_once('\n')?;
    let (copy, csr) = match rest.strip_prefix("copy\t").and_then(|r| r.split_once('\n')) {
        Some((path, csr)) => (Some(path.to_owned()), csr.to_owned()),
        None => (None, rest.to_owned()),
    };
    let state = match first.trim_end().split_once('\t') {
        None if first.trim_end() == "request" => RequestState::Request { csr },
        Some(("signed", issuer)) => RequestState::Signed {
            csr,
            issuer: issuer.to_owned(),
        },
        _ => return None,
    };
    Some((state, copy))
}

pub(super) fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let install = &app.install;
    let row = app.nav.row;
    let busy = app
        .run
        .as_ref()
        .filter(|r| r.running() && matches!(r.work.kind, Kind::Ca { .. }))
        .map(|r| Bar::Busy {
            text: format!("{}…", r.work.kind.doing()),
            tick: app.tick_count,
        });
    let error = install.error.as_ref().map(|e| format!("✗ {e}"));
    if install.requested() {
        // "✓ added" and who, or not yet.
        let added = |said: Option<String>| match said {
            Some(said) => vec![
                Span::styled("✓ added", t.green()),
                Span::styled(said, t.dim()),
            ],
            None => vec![Span::styled("not added yet", t.yellow())],
        };
        let issuer = install
            .signed
            .as_ref()
            .or(install.cert.as_ref().map(|c| &c.1));
        let rows = vec![
            Row::entry("Show the request", "to copy it to your CA"),
            Row::Entry {
                name: vec![Span::raw("Signed certificate")],
                value: added(issuer.map(|who| format!(" · signed by {who}"))),
            },
            Row::Entry {
                name: vec![Span::raw("Your CA's certificate")],
                value: added(install.root_added.as_ref().map(|name| format!(" · {name}"))),
            },
            Row::entry(
                "Next",
                if install.accepted() {
                    "ports"
                } else {
                    "once both are added"
                },
            ),
        ];
        let bar = match row {
            0 => Bar::keys(&[("Enter", "Show the request")]),
            1 | 2 => Bar::keys(&[("Enter", "Open")]),
            _ if install.accepted() => Bar::keys(&[("Enter", "Next")]),
            _ => Bar::keys(&[]),
        };
        let step = Step {
            at: 2,
            rows,
            help: error.as_deref().unwrap_or(MADE),
            red: error.is_some(),
            bar: busy.unwrap_or(bar),
            width: 24,
        };
        return draw_step(frame, head, app, step);
    }
    let radio = |on: bool, name: &str, value: &str| {
        Row::entry(&format!("({}) {name}", if on { "•" } else { " " }), value)
    };
    let mut rows = vec![
        radio(
            install.ca == Ca::Own,
            "Your own CA",
            "your CA signs an intermediate for OpenVIBES",
        ),
        radio(
            install.ca == Ca::OpenVibes,
            "OpenVIBES makes one",
            "a new root CA; its key goes offline after",
        ),
    ];
    let typing = install.editing.is_some();
    if install.ca == Ca::OpenVibes {
        rows.push(Row::entry(
            "Root key file",
            &typed(&install.root_key_out, typing),
        ));
    }
    rows.push(Row::entry("Next", "ports"));
    let next = install.choice_rows() - 1;
    let flagged = (install.ca == Ca::OpenVibes)
        .then(|| fields::check_root_key(install.root_key_out.trim()).err())
        .flatten()
        .map(|why| format!("✗ Root key file: {why}"));
    let help = match row {
        0 | 1 => HELP[row],
        r if r == next => "Go on to the ports.",
        _ => "The CA's root key: written once here, move it offline.",
    };
    let red = flagged.as_ref().or(error.as_ref());
    let bar = match row {
        0 | 1 if !typing => Bar::keys(&[("Space", "Choose")]),
        r => name_bar(typing, r, next, "Next"),
    };
    let step = Step {
        at: 2,
        rows,
        help: red.map_or(help, String::as_str),
        red: red.is_some(),
        bar: busy.unwrap_or(bar),
        width: 24,
    };
    draw_step(frame, head, app, step);
}

/// The request to copy (ca2.py `request`): the PEM, scrolled with ⭡⭣.
pub(super) fn draw_request<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let bar = app.bar(Bar::act(&[(t.up_down(), "Scroll")]));
    let area = frame::draw(frame, t, head, Some("The signing request"), &bar);
    let install = &app.install;
    let saved = install.copy.as_ref().map_or(String::new(), |path| {
        format!(" Also saved as {}", tilde(path, install.home.as_deref()))
    });
    let mut lines = vec![
        Line::raw(""),
        Line::styled(
            "    Select and copy it with your terminal; sign it as an intermediate",
            t.dim(),
        ),
        Line::styled(format!("    (CA:TRUE, pathlen 0).{saved}"), t.dim()),
        Line::raw(""),
    ];
    let pem: Vec<&str> = install.csr().unwrap_or_default().trim().lines().collect();
    let room = usize::from(area.height).saturating_sub(lines.len()).max(3);
    let n = pem.len();
    let row = |l: &str| Line::raw(format!("    {l}"));
    // The first line shown, kept for the keys.
    let top = app.nav.row.min((n + 1).saturating_sub(room));
    app.nav.scroll.set(Scroll { top });
    if n <= room {
        lines.extend(pem.iter().map(|l| row(l)));
    } else {
        // The END line stays in view; "… N more lines" stands for the rest.
        let end = top + room - 2;
        if end + 1 >= n {
            lines.extend(pem[top..].iter().map(|l| row(l)));
        } else {
            lines.extend(pem[top..end].iter().map(|l| row(l)));
            lines.push(Line::styled(
                format!("    … {} more lines", n - 1 - end),
                t.dim(),
            ));
            lines.push(row(pem[n - 1]));
        }
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// Add the signed certificate, or your CA's (ca2.py `how`).
pub(super) fn draw_add<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, which: Which) {
    if let Some(browse) = &app.install.pick {
        return crate::tui::maint::folder::draw_browse(frame, head, app, browse);
    }
    if app.install.paste.is_some() {
        return super::paste::draw(frame, head, app, which);
    }
    let t = &app.theme;
    let title = match which {
        Which::Signed => "Add the signed certificate",
        Which::Root => "Add your CA's certificate",
    };
    let enter = if app.nav.row == 0 {
        "Paste it"
    } else {
        "Choose a file"
    };
    let area = frame::draw(
        frame,
        t,
        head,
        Some(title),
        &app.bar(Bar::keys(&[("Enter", enter)])),
    );
    let rows = [
        Row::entry("Paste it", "paste the PEM text into this terminal"),
        Row::entry(
            "From a file on this host",
            "copied here with scp or a USB stick",
        ),
    ];
    let mut scroll = app.nav.scroll.get();
    let lines = list::lines(t, &rows, app.nav.row, &mut scroll, area.height, 26);
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Step 3's keys.
    pub(super) fn certs_key(&mut self, key: Key) {
        let row = self.nav.row;
        if self.install.requested() {
            if self.move_row(&key, 4) {
                return;
            }
            match (key, row) {
                // Back to the choice; Next asks the helper again.
                (Key::Esc, _) => {
                    self.install.request = None;
                    self.install.error = None;
                    self.install.forget_added();
                    self.nav.row = 0;
                }
                (Key::Enter, 0) => self.nav.go(Screen::Install(Stage::Request)),
                (Key::Enter, 1) => self.nav.go(Screen::Install(Stage::Add(Which::Signed))),
                (Key::Enter, 2) => self.nav.go(Screen::Install(Stage::Add(Which::Root))),
                (Key::Enter, 3) if self.install.accepted() => self.next_step(2),
                _ => {}
            }
            return;
        }
        let count = self.install.choice_rows();
        if self.move_row(&key, count) {
            return;
        }
        match (&key, row) {
            (Key::Esc, _) => self.step_back(2),
            (Key::Char(' ') | Key::Enter, 0 | 1) => {
                self.install.ca = if row == 0 { Ca::Own } else { Ca::OpenVibes };
                self.install.error = None;
                // Your own CA's certificates never go with OpenVIBES's own CA.
                if self.install.ca == Ca::OpenVibes {
                    self.install.request = None;
                    self.install.signed = None;
                    self.install.forget_added();
                }
                if let Key::Enter = key {
                    self.nav.row = self.install.choice_rows() - 1;
                }
            }
            (Key::Enter, 2) if count == 4 => self.edit(2),
            (Key::Enter, r) if r == count - 1 => match self.install.ca {
                Ca::OpenVibes
                    if fields::check_root_key(self.install.root_key_out.trim()).is_ok() =>
                {
                    self.next_step(2)
                }
                Ca::OpenVibes => {}
                Ca::Own => self.make_request(),
            },
            _ => {}
        }
    }

    /// `ca-request`, with a copy in the operator's home: the helper takes
    /// its own copy again, or writes one beside another file, and says
    /// where.
    fn make_request(&mut self) {
        let base =
            (self.install.home.as_ref()).map(|home| format!("{home}/openvibes-intermediate.csr"));
        let call = Call::CaRequest(base);
        self.begin(Work::new(Kind::Ca { accept: false }, vec![call]), 0);
    }

    /// Both certificates added: the helper checks and keeps them.
    pub(super) fn accept_both(&mut self) {
        if let (Some((cert, _)), Some(root)) = (&self.install.cert, &self.install.root_pem) {
            let call = Call::CaAccept(cert.clone(), root.clone());
            self.begin(Work::new(Kind::Ca { accept: true }, vec![call]), 0);
        }
    }

    /// The request's keys: ⭡⭣ scroll from where the last draw stopped,
    /// Esc back.
    pub(super) fn request_key(&mut self, key: Key) {
        let top = self.nav.scroll.get().top;
        match key {
            Key::Down | Key::Char('j') => self.nav.row = top + 1,
            Key::Up | Key::Char('k') => self.nav.row = top.saturating_sub(1),
            Key::Esc => {
                self.nav.pop();
            }
            _ => {}
        }
    }

    /// Add a certificate: Paste it, or From a file on this host.
    pub(super) fn add_key(&mut self, which: Which, key: Key) {
        if self.install.pick.is_some() {
            return self.pick_key(key);
        }
        if self.install.paste.is_some() {
            return self.paste_key(which, key);
        }
        if self.move_row(&key, 2) {
            return;
        }
        match (key, self.nav.row) {
            (Key::Esc, _) => {
                self.nav.pop();
            }
            (Key::Enter, 0) => {
                self.install.paste = Some(String::new());
                self.install.paste_file = None;
            }
            (Key::Enter, _) => {
                let home = self.install.home.clone().unwrap_or_else(|| "/".into());
                self.install.pick = Some(crate::tui::maint::folder::Browse::files_at(&home));
                self.nav.row = 0;
            }
            _ => {}
        }
    }

    /// A CA call ended: the request's state, or why the helper refused.
    pub(super) fn ca_ended(&mut self) {
        let Some(run) = &self.run else { return };
        let Kind::Ca { accept } = run.work.kind else {
            return;
        };
        let install = &mut self.install;
        match &run.states[0] {
            Some(StepState::Done(out)) => match read_state(out) {
                Some((state, copy)) => {
                    if copy.is_some() {
                        install.copy = copy;
                    }
                    if let RequestState::Signed { issuer, .. } = &state {
                        install.signed = Some(issuer.clone());
                        // Your CA's certificate signed it directly: its name.
                        install.root_added.get_or_insert_with(|| issuer.clone());
                        install.cert = None;
                        install.root_pem = None;
                    } else if accept {
                        install.error = Some("The helper did not keep the certificates.".into());
                        install.forget_added();
                        return;
                    }
                    install.request = Some(state);
                    install.error = None;
                    // The request's rows from the top; once both are
                    // added, Next (full_advanced.py).
                    if self.nav.screen == Screen::Install(Stage::Step(2)) {
                        self.nav.row = if accept { 3 } else { 0 };
                    }
                }
                None => install.error = Some(format!("Unexpected helper output: {}", out.trim())),
            },
            Some(state) if !state.finished() => {
                install.error = Some(sentence(state.detail()));
                // Refused: neither row claims "✓ added", both can be added again.
                if accept {
                    install.forget_added();
                }
            }
            _ => {}
        }
    }
}
