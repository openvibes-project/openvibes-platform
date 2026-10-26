//! Maintenance › Certificates › Console certificate (certs4c.py #2-#11):
//! your own certificate for the console in the browser, through the
//! install's Certificate and Private key rows and screens (paste, file,
//! .p12 with its password), checked at once for one of the console's
//! names. Use it asks, and only Yes sends them (`console-cert-set`, under
//! the sudo password); the helper checks everything again. Once yours is
//! in: Use a new one, or Go back to the platform's (`console-cert-reset`).
//! The key is forgotten after the call, and when the page is left.

use platform_host::{Host, StepState};
use ratatui::{Frame, text::Line, widgets::Paragraph};

use super::{Page, Then};
use crate::tui::{
    app::{App, Key, Question},
    ca_request::sentence,
    console_cert_check::console_names,
    install::{Stage, Which, server_check::name_of},
    nav::Screen,
    run::{Call, Kind, Run, Work},
    status::wrap,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};

const NOTE: &str = "For the console in the browser only; agents keep the platform's.";
const SET: &str = "The console uses your certificate";
const RESET: &str = "The console uses the platform's certificate again";

fn console_run<H: Host>(app: &App<H>) -> Option<&Run> {
    (app.run.as_ref()).filter(|r| matches!(r.work.kind, Kind::ConsoleCert { .. }))
}

/// The bar while it runs, else `keys`.
fn bar<H: Host>(app: &App<H>, keys: &[(&str, &str)]) -> Bar {
    match console_run(app).filter(|r| r.running()) {
        Some(run) => Bar::Busy {
            text: format!("{}…", run.work.kind.doing()),
            tick: app.tick_count,
        },
        None => app.bar(Bar::keys(keys)),
    }
}

/// The key is added: Use it sends both.
fn ready<H: Host>(app: &App<H>) -> bool {
    app.install
        .imported
        .as_ref()
        .is_some_and(|i| i.key.is_some())
}

/// Use your own certificate (certs4c.py #2, #6-#8).
pub fn draw_use<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let install = &app.install;
    let mut rows = install.import_rows(t);
    let said = if install.both_added() {
        "the console restarts"
    } else {
        "once both are added"
    };
    rows.push(Row::entry("Use it", said));
    let enter = match app.nav.row {
        0 => Some("Open"),
        1 if install.imported.is_some() => Some("Open"),
        2 if ready(app) => Some("Use it"),
        _ => None,
    };
    let keys: Vec<(&str, &str)> = enter.map(|e| ("Enter", e)).into_iter().collect();
    let area = frame::draw(
        frame,
        t,
        head,
        Some("Use your own certificate"),
        &bar(app, &keys),
    );
    let mut lines = vec![Line::raw(""), Line::styled(format!("    {NOTE}"), t.dim())];
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, 7, 26));
    app.nav.scroll.set(scroll);
    let under = |text: &str, style| {
        wrap(text, 76, 2)
            .into_iter()
            .map(move |l| Line::styled(format!("    {l}"), style))
    };
    if let Some(why) = &install.error {
        lines.extend(under(&format!("✗ {why}"), t.red()));
    }
    if let Some(hint) = install.p12_hint() {
        lines.extend(under(&hint, t.dim()));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// The console's certificate, once yours is in (certs4c.py #10-#11).
pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let enter = ["Use a new one", "Go back"][app.nav.row.min(1)];
    let area = frame::draw(
        frame,
        t,
        head,
        Some("The console's certificate"),
        &bar(app, &[("Enter", enter)]),
    );
    let own = app.maint.certs.own.as_deref().unwrap_or_default();
    let name = name_of(own).unwrap_or_else(|| "your certificate".into());
    let until = platform_pki::not_after(own).map_or_else(
        |_| "a date that cannot be read".into(),
        |end| end.format("%Y-%m-%d").to_string(),
    );
    let mut lines = vec![
        Line::raw(""),
        Line::styled(format!("    Yours: {name}, until {until}."), t.dim()),
    ];
    let rows = [
        Row::entry("Use a new one", "paste or pick, as before"),
        Row::entry(
            "Go back to the platform's",
            "renewed automatically with the agents",
        ),
    ];
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, 5, 26));
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Nothing added yet; the rows check for this console's names.
    pub(super) fn open_console_use(&mut self) {
        let install = &mut self.install;
        install.forget_import();
        install.error = None;
        install.pick = None;
        install.server = Some(console_names(&self.host));
        self.nav.row = 0;
    }

    /// The page was left: what was added is forgotten.
    pub(in crate::tui) fn console_left(&mut self) {
        self.install.forget_import();
        self.install.error = None;
        self.install.server = None;
    }

    pub(super) fn console_use_key(&mut self, key: Key) {
        if self.move_row(&key, 3) || key != Key::Enter {
            return;
        }
        match self.nav.row {
            0 => self.nav.go(Screen::Install(Stage::Add(Which::Cert))),
            1 if self.install.imported.is_some() => {
                self.nav.go(Screen::Install(Stage::Add(Which::Key)))
            }
            2 if ready(self) => return self.ask_console("Use it?", Then::ConsoleCertSet),
            _ => return,
        }
        self.install.error = None;
    }

    pub(super) fn console_key(&mut self, key: Key) {
        if self.move_row(&key, 2) || key != Key::Enter {
            return;
        }
        if self.nav.row == 0 {
            self.open_page(Page::ConsoleUse);
        } else {
            self.ask_console("Go back?", Then::ConsoleCertReset);
        }
    }

    fn ask_console(&mut self, text: &str, then: Then) {
        self.question = Some((
            Question::Maint {
                text: text.into(),
                detail: "the console restarts".into(),
                then,
            },
            true,
        ));
    }

    pub(super) fn console_set_yes(&mut self) {
        let Some(call @ Call::ConsoleCertSet(_)) = self.install.import_call() else {
            return;
        };
        let kind = Kind::ConsoleCert {
            set: true,
            done: SET.into(),
        };
        self.begin(Work::new(kind, vec![call]), 0);
    }

    pub(super) fn console_reset_yes(&mut self) {
        let kind = Kind::ConsoleCert {
            set: false,
            done: RESET.into(),
        };
        self.begin(Work::new(kind, vec![Call::ConsoleCertReset]), 0);
    }

    /// A run ended: one result line; the key is forgotten either way. Back
    /// on the platform's, Certificates shows it.
    pub(super) fn console_cert_ended(&mut self) {
        let Some(run) = self
            .run
            .as_mut()
            .filter(|r| matches!(r.work.kind, Kind::ConsoleCert { .. }) && !r.running())
        else {
            return;
        };
        // Sent or not, no copy of the key stays in the run.
        run.work.wipe();
        let took = run.took();
        let Kind::ConsoleCert { set, done } = &mut run.work.kind else {
            return;
        };
        let set = *set;
        let out = match &run.states[0] {
            Some(StepState::Done(out)) => out.trim_end().to_owned(),
            Some(state) if !state.finished() => {
                self.outcome = Some((false, sentence(state.detail())));
                return self.install.forget_key();
            }
            _ => return self.install.forget_key(),
        };
        // `set<TAB>NAME<TAB>UNTIL`.
        let until =
            (out.lines().find_map(|l| l.strip_prefix("set\t"))).and_then(|l| l.split('\t').nth(1));
        if let Some(until) = until.filter(|_| set) {
            *done = format!("{SET} · until {}", until.trim());
        }
        self.outcome = Some((true, format!("{done}{took}")));
        self.install.forget_key();
        if set {
            // The rows stay added; the key itself is gone.
            self.install.import_done = Some(out);
        } else if self.nav.screen == Screen::Maint(Page::Console) {
            self.nav.pop();
            self.read_certs();
        }
    }
}
