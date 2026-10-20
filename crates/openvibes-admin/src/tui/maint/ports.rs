//! Maintenance › Ports and addresses (spec §6; maint2.py #4-6, maint2b.py
//! #13-17): every port the platform listens on. Enter on a port types a new
//! one, checked as you type; Apply saves the whole plan, restarts, opens
//! the new port and closes the old one.

use platform_host::{Host, Step};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Then, failure, ports_run::draw as draw_run};
use crate::{
    setup::{
        plan::{Plan, plan_of},
        ports::{CONSOLE_DEFAULT, check_ports},
    },
    tui::{
        app::{App, Key, Question},
        run::{Call, Kind, Run, Work},
        ui::{
            bar::Bar,
            frame,
            list::{self, Row},
            logo::Header,
        },
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortRow {
    Console,
    Ingest,
    Distribution,
}

impl PortRow {
    const ALL: [PortRow; 3] = [PortRow::Console, PortRow::Ingest, PortRow::Distribution];

    fn name(self) -> &'static str {
        match self {
            PortRow::Console => "Console",
            PortRow::Ingest => "Agent connections",
            PortRow::Distribution => "Rule distribution",
        }
    }
    fn of(self, plan: &Plan) -> u16 {
        match self {
            PortRow::Console => plan.console_port,
            PortRow::Ingest => plan.ingest_port,
            PortRow::Distribution => plan.distribution_port,
        }
    }
    fn set(self, plan: &mut Plan, port: u16) {
        match self {
            PortRow::Console => plan.console_port = port,
            PortRow::Ingest => plan.ingest_port = port,
            PortRow::Distribution => plan.distribution_port = port,
        }
    }
}

/// What the line under the list says of `typed` as `row`'s port: `Ok` when
/// it can be used, `Err` (drawn red) when not. `plan` is the plan as it
/// stands; its value for `row` counts as free, because the platform's own
/// service holds it and the unprivileged check cannot tell who does.
pub fn port_note<H: Host>(
    host: &H,
    plan: &Plan,
    row: PortRow,
    typed: &str,
) -> Result<String, String> {
    let Ok(port) = typed.parse::<u16>() else {
        return Err("✗ a port is a number from 1 to 65535.".into());
    };
    if let Some(other) = PortRow::ALL
        .iter()
        .find(|r| **r != row && r.of(plan) == port)
    {
        return Err(format!(
            "✗ {port} is already used here for {}.",
            other.name()
        ));
    }
    let mut asked = plan.clone();
    row.set(&mut asked, port);
    check_ports(
        asked.console_port,
        asked.ingest_port,
        asked.distribution_port,
    )
    .map_err(|why| format!("✗ {why}."))?;
    if port != row.of(plan) {
        let seen = host.listeners(port).map_err(|e| format!("✗ {e}."))?;
        if !seen.trim().is_empty() {
            return Err(format!(
                "✗ {port} is used by another program on this host: choose another."
            ));
        }
    }
    Ok(format!("{port} is free on this host."))
}

/// The page's state: the saved plan, the plan with the edits, the port
/// being typed.
#[derive(Debug, Default)]
pub struct Ports {
    saved: Option<Plan>,
    now: Option<Plan>,
    error: Option<String>,
    /// The digits typed for the row under the cursor.
    typing: Option<String>,
    note: Option<Result<String, String>>,
}

impl Ports {
    pub fn typing(&self) -> bool {
        self.typing.is_some()
    }

    /// The rows whose port differs from the saved plan.
    fn moved(&self) -> Vec<PortRow> {
        match (&self.saved, &self.now) {
            (Some(was), Some(now)) => PortRow::ALL
                .into_iter()
                .filter(|r| r.of(was) != r.of(now))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn agent_moved(&self) -> bool {
        self.moved().iter().any(|r| *r != PortRow::Console)
    }

    /// Rows in the list: the four ports, then Apply once something changed.
    fn count(&self) -> usize {
        if self.moved().is_empty() { 4 } else { 5 }
    }

    /// `https://host[:port]`.
    fn address(&self) -> String {
        let plan = self.now.as_ref().expect("a plan");
        web(&plan.hostname, plan.console_port)
    }

    /// The result line (without the time).
    fn done(&self) -> String {
        let moved = self.moved();
        let plan = self.now.as_ref().expect("a plan");
        match moved.as_slice() {
            [PortRow::Console] => format!(
                "Console moved to {} · {}",
                plan.console_port,
                self.address()
            ),
            [one] => format!(
                "Moved to {} · new install line: console › Enrollment",
                one.of(plan)
            ),
            many => format!(
                "Moved {} ports · new install line: console › Enrollment",
                many.len()
            ),
        }
    }

    /// One row per call group, in the real order of the work.
    fn work(&self) -> Option<Work> {
        let plan = self.now.as_ref()?;
        let before = |end: Step| -> Vec<Call> {
            Step::ALL
                .iter()
                .take_while(|s| **s != end)
                .map(|s| Call::Repair(*s))
                .collect()
        };
        let services: Vec<Call> = before(Step::Firewall);
        let open: Vec<Call> = Step::ALL
            .iter()
            .skip_while(|s| **s != Step::Firewall)
            .take_while(|s| **s != Step::Ready)
            .map(|s| Call::Repair(*s))
            .collect();
        let what = match self.moved().as_slice() {
            [PortRow::Console] => "Moving the console",
            [PortRow::Ingest] => "Moving agent connections",
            [PortRow::Distribution] => "Moving rule distribution",
            _ => "Moving ports",
        };
        let groups = vec![
            (
                "Save the ports".to_owned(),
                vec![Call::SetupPlan(plan.args())],
            ),
            ("Restart with the new port".to_owned(), services),
            ("Open the new port".to_owned(), open),
            (
                "Close the old port".to_owned(),
                vec![Call::Repair(Step::Ready)],
            ),
            (
                "Ready".to_owned(),
                vec![Call::Repair(Step::AssistantModel), Call::Status],
            ),
        ];
        Some(Work::grouped(
            Kind::Ports {
                what: what.into(),
                done: self.done(),
            },
            groups,
        ))
    }
}

/// `https://host`, with `:port` unless it is the default.
fn web(host: &str, port: u16) -> String {
    if port == CONSOLE_DEFAULT {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    }
}

fn ports_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Ports { .. }))
}

fn row<H: Host>(app: &App<H>, ports: &Ports, at: usize) -> Row {
    let t = &app.theme;
    let (Some(was), Some(now)) = (&ports.saved, &ports.now) else {
        return Row::entry("", "");
    };
    if at == 3 {
        return Row::entry("Network devices", "514/udp");
    }
    if at == 4 {
        let says = if ports.agent_moved() {
            "agents must be told the new port"
        } else {
            "the web address changes"
        };
        return Row::entry("Apply", says);
    }
    let r = PortRow::ALL[at];
    let (old, new) = (r.of(was), r.of(now));
    let typed = app.nav.row == at && ports.typing.is_some();
    let dim = |s: String| vec![Span::styled(s, t.dim())];
    if let (true, Some(text)) = (typed, &ports.typing) {
        return Row::Entry {
            name: vec![Span::raw(r.name())],
            value: dim(format!("{text}█")),
        };
    }
    if ports.typing.is_some() {
        return Row::Entry {
            name: vec![Span::raw(r.name())],
            value: dim(new.to_string()),
        };
    }
    if old != new {
        return Row::Entry {
            name: vec![
                Span::styled("*", t.yellow()),
                Span::raw(format!(" {}", r.name())),
            ],
            value: dim(format!("{new} · was {old}")),
        };
    }
    let value = match r {
        PortRow::Console => format!("{new} · {}", web(&now.hostname, new)),
        _ => new.to_string(),
    };
    Row::Entry {
        name: vec![Span::raw(r.name())],
        value: dim(value),
    }
}

fn help<H: Host>(app: &App<H>) -> Line<'static> {
    let t = &app.theme;
    let ports = &app.maint.ports;
    if ports.typing.is_some() {
        return match &ports.note {
            Some(Err(why)) => Line::styled(format!("    {why}"), t.red()),
            Some(Ok(ok)) => Line::styled(format!("    {ok}"), t.dim()),
            None => Line::raw(""),
        };
    }
    let text = match app.nav.row {
        0 => "The console's port; the web address follows it.".to_owned(),
        1 => "The port agents send their findings to.".into(),
        2 => "The port agents fetch their rules from.".into(),
        3 => "Network devices send their logs here; it is not changed on this page.".into(),
        _ if ports.agent_moved() => {
            "Agents on other hosts need their install line again after this.".into()
        }
        _ => format!("The console's web address changes to {}.", ports.address()),
    };
    Line::styled(format!("    {text}"), t.dim())
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = ports_run(app) {
        return draw_run(frame, head, app, run);
    }
    let t = &app.theme;
    let ports = &app.maint.ports;
    let bar = if ports.error.is_some() {
        Bar::act(&[])
    } else if ports.typing.is_some() {
        let name = PortRow::ALL[app.nav.row.min(2)].name();
        Bar::edit(name, "type a port", &[("Enter", "Done")])
    } else {
        match app.nav.row {
            0..=2 => Bar::keys(&[("Enter", "Change")]),
            3 => Bar::keys(&[]),
            _ => Bar::keys(&[("Enter", "Apply")]),
        }
    };
    let area = frame::draw(frame, t, head, Some("Ports and addresses"), &app.bar(bar));
    if let Some(error) = &ports.error {
        let lines = failure(t, error, "Nothing was changed.");
        return frame.render_widget(Paragraph::new(lines), area);
    }
    let rows: Vec<Row> = (0..ports.count()).map(|i| row(app, ports, i)).collect();
    let mut scroll = app.nav.scroll.get();
    let mut lines = list::lines(t, &rows, app.nav.row, &mut scroll, 11, 22);
    app.nav.scroll.set(scroll);
    lines.push(help(app));
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_ports(&mut self) {
        self.nav.row = 0;
        // A successful run's result is not news the next time; a failed one
        // stays, with its Try again.
        if self
            .run
            .as_ref()
            .is_some_and(|r| r.ok() && matches!(r.work.kind, Kind::Ports { .. }))
        {
            self.run = None;
        }
        let read = self
            .host
            .setup_plan()
            .map_err(|e| e.to_string())
            .and_then(|text| plan_of(&text));
        self.maint.ports = match read {
            Ok(plan) => Ports {
                saved: Some(plan.clone()),
                now: Some(plan),
                ..Ports::default()
            },
            Err(error) => Ports {
                error: Some(format!("The plan cannot be read: {error}")),
                ..Ports::default()
            },
        };
    }

    /// The note for what is typed: the plan with this row's own port as it
    /// was saved, the other rows as edited.
    fn port_check(&mut self, row: PortRow) {
        let ports = &self.maint.ports;
        let (Some(saved), Some(now), Some(typed)) = (&ports.saved, &ports.now, &ports.typing)
        else {
            return;
        };
        let mut probe = now.clone();
        row.set(&mut probe, row.of(saved));
        let note = port_note(&self.host, &probe, row, typed);
        self.maint.ports.note = Some(note);
    }

    fn ports_typed(&mut self, key: Key) {
        let row = PortRow::ALL[self.nav.row.min(2)];
        let ports = &mut self.maint.ports;
        let Some(text) = ports.typing.as_mut() else {
            return;
        };
        match key {
            Key::Char(c) if c.is_ascii_digit() && text.len() < 5 => text.push(c),
            Key::Backspace => {
                text.pop();
            }
            Key::ClearLine => text.clear(),
            Key::Enter => {
                if let (Some(Ok(_)), Ok(port), Some(now)) =
                    (&ports.note, text.parse::<u16>(), ports.now.as_mut())
                {
                    row.set(now, port);
                    ports.typing = None;
                    ports.note = None;
                }
                return;
            }
            Key::Esc => {
                ports.typing = None;
                ports.note = None;
                return;
            }
            _ => return,
        }
        self.port_check(row);
    }

    pub(super) fn ports_key(&mut self, key: Key) {
        if self.maint.ports.typing() {
            return self.ports_typed(key);
        }
        if let Some(run) = ports_run(self) {
            if run.running() || key != Key::Enter {
                return;
            }
            if run.ok() {
                self.run = None;
                self.back();
            } else if let Some(at) = run.stopped_at() {
                let work = run.work.clone();
                self.begin(work, at);
            }
            return;
        }
        let count = self.maint.ports.count();
        if self.maint.ports.now.is_none() || self.move_row(key, count) || key != Key::Enter {
            return;
        }
        match self.nav.row {
            row @ 0..=2 => {
                let ports = &mut self.maint.ports;
                let now = ports.now.as_ref().expect("a plan");
                ports.typing = Some(PortRow::ALL[row].of(now).to_string());
                self.port_check(PortRow::ALL[row]);
            }
            4 => self.ask_ports(),
            _ => {}
        }
    }

    fn ask_ports(&mut self) {
        let moved = self.maint.ports.moved();
        if moved.is_empty() {
            return;
        }
        if let Some(why) = super::blocked_by_half_done(self) {
            self.outcome = Some((false, why));
            return;
        }
        let now = self.maint.ports.now.as_ref().expect("a plan");
        // Question and detail fit 40 columns, so the buttons always show.
        let (text, detail) = match moved.as_slice() {
            [PortRow::Ingest] => (
                format!("Move agents to {}?", PortRow::Ingest.of(now)),
                "new install line",
            ),
            [PortRow::Distribution] => (
                format!("Move distribution to {}?", PortRow::Distribution.of(now)),
                "",
            ),
            [PortRow::Console] => (
                format!("Move the console to {}?", now.console_port),
                "new address",
            ),
            many => (format!("Move {} ports?", many.len()), "new install line"),
        };
        self.question = Some((
            Question::Maint {
                text,
                detail: detail.into(),
                then: Then::Ports,
            },
            true,
        ));
    }

    pub(super) fn ports_yes(&mut self) {
        if let Some(work) = self.maint.ports.work() {
            self.begin(work, 0);
        }
    }
}
