//! Choose what to install (advanced.py, full_advanced.py): the steps line
//! and steps 1, 2, 4 and 5 (Optional, Names, Ports, Review); step 3 is in
//! `certs.rs`. Enter on Next moves on, Esc goes back a step; fields are
//! edited in place.

use std::path::Path;

use platform_host::Host;
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Ca, Install, Stage, fields};
use crate::{
    setup::plan::{CaMode, Component},
    tui::{
        app::{App, Key},
        nav::{Nav, Screen},
        status::wrap,
        ui::{
            bar::Bar,
            frame,
            list::{self, Row},
            logo::Header,
            theme::Theme,
        },
    },
};

pub(super) const STEPS: [&str; 5] = ["Optional", "Names", "Certificates", "Ports", "Review"];

pub(super) fn exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// `✓ done · ● current · ○ to come`.
fn steps_line(t: &Theme, at: u8) -> Line<'static> {
    let mut spans = vec![Span::raw("   ")];
    for (i, name) in STEPS.iter().enumerate() {
        spans.push(Span::raw(" "));
        match i.cmp(&usize::from(at)) {
            std::cmp::Ordering::Less => {
                spans.push(Span::styled("✓", t.green()));
                spans.push(Span::styled(format!(" {name} "), t.dim()));
            }
            std::cmp::Ordering::Equal => {
                spans.push(Span::styled("●", t.teal()));
                spans.push(Span::styled(format!(" {name} "), t.bold()));
            }
            std::cmp::Ordering::Greater => spans.push(Span::styled(format!("○ {name} "), t.dim())),
        }
    }
    Line::from(spans)
}

/// One step: the steps line, `rows`, then `help` (red when it flags a field).
pub(super) struct Step<'a> {
    pub at: u8,
    pub rows: Vec<Row>,
    pub help: &'a str,
    pub red: bool,
    pub bar: Bar,
    pub width: usize,
}

pub(super) fn draw_step<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, step: Step) {
    let t = &app.theme;
    let area = frame::draw(frame, t, head, None, &app.bar(step.bar));
    let help = wrap(step.help, 76, 2);
    // The help line follows the list (advanced.py `step`), which takes no
    // more than its rows and the two hint lines.
    let room = area
        .height
        .saturating_sub(1 + help.len() as u16)
        .min(step.rows.len() as u16 * 2 + 1);
    let mut lines = vec![steps_line(t, step.at)];
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(
        t,
        &step.rows,
        app.nav.row,
        &mut scroll,
        room,
        step.width,
    ));
    app.nav.scroll.set(scroll);
    let style = if step.red { t.red() } else { t.dim() };
    lines.extend(
        help.into_iter()
            .map(|l| Line::styled(format!("    {l}"), style)),
    );
    frame.render_widget(Paragraph::new(lines), area);
}

/// A checkbox row: `[x]` in green when ticked.
pub(super) fn check_row(t: &Theme, on: bool, name: &str, value: &str) -> Row {
    let mark = if on {
        Span::styled("[x]", t.green())
    } else {
        Span::raw("[ ]")
    };
    Row::Entry {
        name: vec![mark, Span::raw(format!(" {name}"))],
        value: vec![Span::styled(value.to_owned(), t.dim())],
    }
}

/// A field's value, with the cursor while it is typed.
pub(super) fn typed(text: &str, typing: bool) -> String {
    format!("{text}{}", if typing { "█" } else { "" })
}

/// `path` with the home folder as `~`.
pub(super) fn tilde(path: &str, home: Option<&str>) -> String {
    match home.and_then(|h| path.strip_prefix(&format!("{h}/"))) {
        Some(rest) => format!("~/{rest}"),
        None => path.to_owned(),
    }
}

impl Install {
    /// The field typed in place at `step`'s `row`.
    fn step_field(&mut self, step: u8, row: usize) -> Option<&mut String> {
        match (step, row) {
            (1, 0) => Some(&mut self.hostname),
            (1, 1) => Some(&mut self.sans),
            (2, 2) if self.ca == Ca::OpenVibes => Some(&mut self.root_key_out),
            (3, 0) => Some(&mut self.console_port),
            (3, 1) => Some(&mut self.ingest_port),
            (3, 2) => Some(&mut self.distribution_port),
            _ => None,
        }
    }

    /// #87: the choices of the `setup.toml` a first install that stopped
    /// before its CA left, with a free root key name (looked up now: a
    /// key written since, or kept by Remove everything, is taken).
    pub(super) fn fill_from(&mut self, text: &str) -> Result<(), String> {
        let plan = toml::from_str::<crate::setup::plan::Plan>(text).map_err(|e| e.to_string())?;
        self.agent = plan.components.contains(&Component::Agent);
        self.assistant = plan.components.contains(&Component::Assistant);
        self.hostname = plan.hostname;
        self.sans = plan.sans.join(", ");
        self.ca = match plan.ca {
            CaMode::Careful => Ca::Own,
            CaMode::Quick => Ca::OpenVibes,
        };
        self.root_key_out = super::fields::default_root_key(self.home.as_deref());
        self.console_port = plan.console_port.to_string();
        self.ingest_port = plan.ingest_port.to_string();
        self.distribution_port = plan.distribution_port.to_string();
        self.proposed = [None, None, None];
        self.port_note = None;
        Ok(())
    }
}

pub(super) fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, at: u8) {
    match at {
        0 => draw_optional(frame, head, app),
        1 => draw_names(frame, head, app),
        2 => super::certs::draw(frame, head, app),
        3 => super::review::draw_ports(frame, head, app),
        _ => super::review::draw_review(frame, head, app),
    }
}

/// Step 1: only the optional parts; the core is always installed.
fn draw_optional<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let install = &app.install;
    let row = app.nav.row;
    let help = [
        "Untick only if this server must not run an agent.",
        "Answers questions about your findings, on this host, no cloud. Needs 4 GB.",
        "Go on to the names this host is reached by.",
    ][row.min(2)];
    let step = Step {
        at: 0,
        rows: vec![
            check_row(
                t,
                install.agent,
                "Agent on this host",
                "watch this host too",
            ),
            check_row(
                t,
                install.assistant,
                "Assistant",
                "local AI helper · 2.7 GB download",
            ),
            Row::entry("Next", "names"),
        ],
        // A #87 plan that did not read says why here.
        help: install.error.as_deref().unwrap_or(help),
        red: install.error.is_some(),
        bar: if row == 2 {
            Bar::keys(&[("Enter", "Next")])
        } else {
            Bar::keys(&[("Space", "Select/deselect"), ("Enter", "Confirm")])
        },
        width: 26,
    };
    draw_step(frame, head, app, step);
}

/// Step 2: the names, edited in place; a bad one is flagged in red.
fn draw_names<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let install = &app.install;
    let row = app.nav.row;
    let typing = |r: usize| install.editing.is_some() && row == r;
    let flagged = fields::check_names(&install.hostname, "")
        .map_err(|why| format!("✗ Host name: {why}"))
        .and_then(|()| {
            fields::check_names(&install.hostname, &install.sans)
                .map_err(|why| format!("✗ Other names: {why}"))
        })
        .err();
    let help = [
        "The name agents and your browser use to reach this host.",
        "Other names or addresses agents may use, comma-separated.",
        "Go on to the certificates.",
    ][row.min(2)];
    let step = Step {
        at: 1,
        rows: vec![
            Row::entry("Host name", &typed(&install.hostname, typing(0))),
            Row::entry("Other names", &typed(&install.sans, typing(1))),
            Row::entry("Next", "certificates"),
        ],
        help: flagged.as_deref().unwrap_or(help),
        red: flagged.is_some(),
        bar: name_bar(install.editing.is_some(), row, 2, "Next"),
        width: 22,
    };
    draw_step(frame, head, app, step);
}

/// The bar of a step with typed fields: Change, the edit, or `next` on Next.
pub(super) fn name_bar(editing: bool, row: usize, next_row: usize, next: &str) -> Bar {
    match (editing, row) {
        (true, 0) => Bar::edit("Host name", "type", &[("Enter", "Done")]),
        (true, 1) => Bar::edit("Other names", "type", &[("Enter", "Done")]),
        (true, _) => Bar::edit("Root key file", "type a path", &[("Enter", "Done")]),
        (_, r) if r == next_row => Bar::keys(&[("Enter", next)]),
        _ => Bar::keys(&[("Enter", "Change")]),
    }
}

impl<H: Host> App<H> {
    /// A step's keys; step 3 has its own (`certs_key`).
    pub(super) fn step_key(&mut self, at: u8, key: Key) {
        if self.install.editing.is_some() {
            return self.field_key(at, key);
        }
        if at == 2 {
            return self.certs_key(key);
        }
        let count = if at < 3 { 3 } else { 5 };
        let row = self.nav.row;
        // Ports: a digit on a moved port types another one.
        if let (3, Key::Char(c)) = (at, &key)
            && c.is_ascii_digit()
            && row < 3
        {
            self.edit(at);
            if let Some(text) = self.install.step_field(at, row) {
                text.clear();
            }
            return self.field_key(at, key);
        }
        if self.move_row(&key, count) {
            return;
        }
        match (at, key, row) {
            (_, Key::Esc, _) => self.step_back(at),
            (0, Key::Char(' '), 0) => self.install.agent = !self.install.agent,
            (0, Key::Char(' '), 1) => self.install.assistant = !self.install.assistant,
            (0, Key::Enter, 0 | 1) => self.nav.row = 2,
            (1, Key::Enter, 0 | 1) => self.edit(at),
            (1, Key::Enter, 2)
                if fields::check_names(&self.install.hostname, &self.install.sans).is_ok() =>
            {
                self.next_step(at)
            }
            (3, Key::Enter, 0..=2) if self.install.proposed[row].is_some() => {
                self.install.proposed[row] = None;
            }
            (3, Key::Enter, 0..=2) => self.edit(at),
            (4, Key::Enter, 0..=3) => {
                self.nav.row = 0;
                self.nav.screen = Screen::Install(Stage::Step(row as u8));
            }
            (4, Key::Enter, 4) if self.install.not_ready().is_none() => self.start_install(),
            (0 | 3, Key::Enter, r) if r == count - 1 => self.next_step(at),
            _ => {}
        }
    }

    /// Starts typing the field under the cursor.
    pub(super) fn edit(&mut self, at: u8) {
        let row = self.nav.row;
        if let Some(text) = self.install.step_field(at, row) {
            self.install.editing = Some(text.clone());
            if at == 3 {
                self.install.port_check = Some(self.install.port_check(&self.host, row));
            }
        }
    }

    /// A field typed in place: Enter keeps it (a port only when it can be
    /// used), Esc puts it back.
    fn field_key(&mut self, at: u8, key: Key) {
        let row = self.nav.row;
        let Some(was) = self.install.editing.clone() else {
            return;
        };
        let port_ok = matches!(self.install.port_check, Some(Ok(_)));
        let Some(text) = self.install.step_field(at, row) else {
            self.install.editing = None;
            return;
        };
        let max = if at == 2 { 4096 } else { 253 };
        match key {
            Key::Char(c)
                if !c.is_control() && text.len() < max && (at != 3 || c.is_ascii_digit()) =>
            {
                text.push(if at == 1 { c.to_ascii_lowercase() } else { c });
            }
            Key::Backspace => {
                text.pop();
            }
            Key::ClearLine => text.clear(),
            Key::Enter if at == 3 && !port_ok => {}
            Key::Enter => {
                self.install.editing = None;
                if at == 3 {
                    self.install.proposed[row] = None;
                }
            }
            Key::Esc => {
                *text = was;
                self.install.editing = None;
            }
            _ => {}
        }
        if at == 3 && self.install.editing.is_some() {
            self.install.port_check = Some(self.install.port_check(&self.host, row));
        }
    }

    pub(super) fn next_step(&mut self, at: u8) {
        self.install.error = None;
        self.nav.screen = Screen::Install(Stage::Step(at + 1));
        // Review opens on Install.
        self.nav.row = if at + 1 == 4 { 4 } else { 0 };
    }

    /// Esc: a step back; from step 1, Welcome on a fresh host and Home
    /// on one whose first install stopped before its CA (#87).
    pub(super) fn step_back(&mut self, at: u8) {
        self.nav.row = 0;
        match at {
            0 if self.host.is_set_up() => self.nav = Nav::new(Screen::Home),
            0 => self.nav.screen = Screen::Install(Stage::Welcome),
            _ => self.nav.screen = Screen::Install(Stage::Step(at - 1)),
        }
    }

    /// #87: opens step 1, filled from `setup.toml`; a plan that does not
    /// read keeps the defaults and says why.
    pub(in crate::tui) fn open_steps_from_plan(&mut self) {
        self.nav = Nav::new(Screen::Install(Stage::Step(0)));
        let filled = self
            .host
            .setup_plan()
            .map_err(|e| e.to_string())
            .and_then(|text| self.install.fill_from(&text));
        self.install.error = filled.err();
        // A port the plan chose that another program holds now is moved
        // and said, unless the platform's own service holds it (#115).
        let units = [
            platform_host::Unit::Console,
            platform_host::Unit::Ingest,
            platform_host::Unit::Distribution,
        ];
        let services = &self.services;
        let ours = |i: usize| {
            services
                .iter()
                .any(|s| s.unit == units[i] && s.active == "active")
        };
        self.install.port_note = fields::propose_ports(&self.host, &mut self.install, ours);
    }
}
