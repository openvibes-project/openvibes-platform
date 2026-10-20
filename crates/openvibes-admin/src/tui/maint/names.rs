//! Maintenance › Certificates › Names (maint2b.py #19-23): the host name and
//! the other names the server certificates cover. Enter on a name types
//! it, checked as you type; Apply saves the whole plan and issues new
//! certificates.

use std::net::IpAddr;

use platform_host::{Host, Step};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Then, failure, ports_run::draw as draw_run};
use crate::{
    setup::plan::{MAX_SANS, Plan, check_name, check_san, plan_of},
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

const DOTS: &str = "✗ Not a DNS name or an address: letters, digits, dots and dashes.";

/// What a list row is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum At {
    Host,
    Other(usize),
    /// The name being added, not in the plan yet.
    New,
    Add,
    Apply,
}

/// The page's state: the saved plan, the plan with the edits, the name
/// being typed.
#[derive(Debug, Default)]
pub struct Names {
    saved: Option<Plan>,
    now: Option<Plan>,
    error: Option<String>,
    /// The text typed for the row under the cursor.
    typing: Option<String>,
    /// The typed text is a new name (the row before Add a name).
    adding: bool,
    note: Option<Result<String, String>>,
}

impl Names {
    pub fn typing(&self) -> bool {
        self.typing.is_some()
    }

    fn changed(&self) -> bool {
        match (&self.saved, &self.now) {
            (Some(was), Some(now)) => was.hostname != now.hostname || was.sans != now.sans,
            _ => false,
        }
    }

    fn rows(&self) -> Vec<At> {
        let Some(now) = &self.now else {
            return Vec::new();
        };
        let mut rows = vec![At::Host];
        rows.extend((0..now.sans.len()).map(At::Other));
        if self.adding {
            rows.push(At::New);
        }
        rows.push(At::Add);
        if self.changed() {
            rows.push(At::Apply);
        }
        rows
    }

    /// What the line under the list says of `typed` for the row `at`:
    /// `Ok` when it can be used, `Err` (drawn red) when not.
    fn note_for(&self, at: At, typed: &str) -> Option<Result<String, String>> {
        let now = self.now.as_ref()?;
        if typed.is_empty() {
            return match at {
                At::Host => Some(Err("✗ The host name is needed.".into())),
                At::Other(_) => Some(Ok("Enter removes this name.".into())),
                _ => None,
            };
        }
        let valid = if at == At::Host {
            check_name(typed).map_err(|_| "✗ Not a DNS name: letters, digits, dots and dashes.")
        } else {
            check_san(typed).map_err(|_| DOTS)
        };
        if let Err(why) = valid {
            return Some(Err(why.into()));
        }
        let own = match at {
            At::Other(i) => Some(&now.sans[i]),
            _ => None,
        };
        let others = std::iter::once(&now.hostname).filter(|_| at != At::Host);
        let elsewhere = others.chain(now.sans.iter().filter(|s| Some(*s) != own));
        if elsewhere.into_iter().any(|n| n == typed) {
            return Some(Err("✗ That name is already in the list.".into()));
        }
        Some(Ok(if typed.parse::<IpAddr>().is_ok() {
            "An address.".into()
        } else {
            "A valid DNS name.".into()
        }))
    }

    fn done(&self) -> String {
        let n = 1 + self.now.as_ref().map_or(0, |p| p.sans.len());
        format!(
            "New certificates with {n} name{}",
            if n == 1 { "" } else { "s" }
        )
    }

    /// One row per call group, in the real order of the work.
    fn work(&self) -> Option<Work> {
        let plan = self.now.as_ref()?;
        let from = |a: Step, b: Step| -> Vec<Call> {
            Step::ALL
                .iter()
                .skip_while(|s| **s != a)
                .take_while(|s| **s != b)
                .map(|s| Call::Repair(*s))
                .collect()
        };
        let groups = vec![
            (
                "Save the names".to_owned(),
                vec![Call::SetupPlan(plan.args())],
            ),
            (
                "New certificates".to_owned(),
                from(Step::Packages, Step::Console),
            ),
            (
                "Restart services".to_owned(),
                from(Step::Console, Step::Ready),
            ),
            (
                "Ready".to_owned(),
                vec![
                    Call::Repair(Step::Ready),
                    Call::Repair(Step::AssistantModel),
                    Call::Status,
                ],
            ),
        ];
        Some(Work::grouped(
            Kind::Names {
                what: "New certificates".into(),
                done: self.done(),
            },
            groups,
        ))
    }
}

fn names_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Names { .. }))
}

fn row<H: Host>(app: &App<H>, at: At, names: &Names) -> Row {
    let t = &app.theme;
    let (Some(was), Some(now)) = (&names.saved, &names.now) else {
        return Row::entry("", "");
    };
    let dim = |s: String| vec![Span::styled(s, t.dim())];
    let plain = |name: &str, value: String| Row::Entry {
        name: vec![Span::raw(name.to_owned())],
        value: dim(value),
    };
    let marked = |name: &str, value: String| Row::Entry {
        name: vec![Span::styled("*", t.yellow()), Span::raw(format!(" {name}"))],
        value: dim(value),
    };
    let typed = names
        .typing
        .as_ref()
        .filter(|_| names.rows().get(app.nav.row) == Some(&at));
    let name = if matches!(at, At::Host) {
        "Host name"
    } else {
        "Other name"
    };
    if let Some(text) = typed {
        return plain(name, format!("{text}█"));
    }
    match at {
        At::Host if now.hostname != was.hostname => {
            marked(name, format!("{} · was {}", now.hostname, was.hostname))
        }
        At::Host => plain(name, now.hostname.clone()),
        At::Other(i) if !was.sans.contains(&now.sans[i]) => {
            marked(name, format!("{} · new", now.sans[i]))
        }
        At::Other(i) => plain(name, now.sans[i].clone()),
        At::New => plain(name, "█".into()),
        At::Add => plain("Add a name", "an address or DNS name".into()),
        At::Apply => plain("Apply", "new certificates with these names".into()),
    }
}

fn help<H: Host>(app: &App<H>, names: &Names, at: Option<At>) -> Line<'static> {
    let t = &app.theme;
    if names.typing.is_some() {
        return match &names.note {
            Some(Err(why)) => Line::styled(format!("    {why}"), t.red()),
            Some(Ok(ok)) => Line::styled(format!("    {ok}"), t.dim()),
            None => Line::raw(""),
        };
    }
    let text = match at {
        Some(At::Host) => "The name this host is known by.",
        Some(At::Other(_)) => "A name or address agents and browsers may use.",
        Some(At::Add) => "Names agents and browsers may use to reach this host.",
        Some(At::Apply) => "Agents keep working; browsers see the new names.",
        _ => "",
    };
    Line::styled(format!("    {text}"), t.dim())
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = names_run(app) {
        return draw_run(frame, head, app, run);
    }
    let t = &app.theme;
    let names = &app.maint.names;
    let rows = names.rows();
    let at = rows.get(app.nav.row).copied();
    let bar = if names.error.is_some() {
        Bar::act(&[])
    } else if names.typing.is_some() {
        let label = if at == Some(At::Host) {
            "Host name"
        } else {
            "Other name"
        };
        Bar::edit(label, "type a name", &[("Enter", "Done")])
    } else {
        match at {
            Some(At::Host | At::Other(_)) => Bar::keys(&[("Enter", "Change")]),
            Some(At::Add) => Bar::keys(&[("Enter", "Add")]),
            _ => Bar::keys(&[("Enter", "Apply")]),
        }
    };
    let area = frame::draw(frame, t, head, Some("Names"), &app.bar(bar));
    if let Some(error) = &names.error {
        let lines = failure(t, error, "Nothing was changed.");
        return frame.render_widget(Paragraph::new(lines), area);
    }
    let list_rows: Vec<Row> = rows.iter().map(|r| row(app, *r, names)).collect();
    let height = (2 * rows.len() as u16 + 1).min(area.height.saturating_sub(1));
    let mut scroll = app.nav.scroll.get();
    let mut lines = list::lines(t, &list_rows, app.nav.row, &mut scroll, height, 22);
    app.nav.scroll.set(scroll);
    lines.push(help(app, names, at));
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_names(&mut self) {
        self.nav.row = 0;
        // A successful run's result is not news the next time; a failed one
        // stays, with its Try again.
        if self
            .run
            .as_ref()
            .is_some_and(|r| r.ok() && matches!(r.work.kind, Kind::Names { .. }))
        {
            self.run = None;
        }
        let read = self
            .host
            .setup_plan()
            .map_err(|e| e.to_string())
            .and_then(|text| plan_of(&text));
        self.maint.names = match read {
            Ok(plan) => Names {
                saved: Some(plan.clone()),
                now: Some(plan),
                ..Names::default()
            },
            Err(error) => Names {
                error: Some(format!("The plan cannot be read: {error}")),
                ..Names::default()
            },
        };
    }

    fn name_at(&self) -> Option<At> {
        self.maint.names.rows().get(self.nav.row).copied()
    }

    fn name_check(&mut self) {
        let names = &self.maint.names;
        let (Some(at), Some(typed)) = (self.name_at(), &names.typing) else {
            return;
        };
        self.maint.names.note = names.note_for(at, typed);
    }

    fn names_typed(&mut self, key: Key) {
        let at = self.name_at();
        let names = &mut self.maint.names;
        let Some(text) = names.typing.as_mut() else {
            return;
        };
        match key {
            Key::Char(c) if !c.is_control() && text.len() < 253 => text.push(c),
            Key::Backspace => {
                text.pop();
            }
            Key::ClearLine => text.clear(),
            Key::Enter => {
                let typed = std::mem::take(text);
                let Some(now) = names.now.as_mut() else {
                    return;
                };
                match (at, names.note.clone()) {
                    (Some(At::Other(i)), Some(Ok(_))) if typed.is_empty() => {
                        now.sans.remove(i);
                    }
                    (Some(At::Host), Some(Ok(_))) => now.hostname = typed,
                    (Some(At::Other(i)), Some(Ok(_))) => now.sans[i] = typed,
                    (Some(At::New), Some(Ok(_))) => now.sans.push(typed),
                    _ => {
                        names.typing = Some(typed);
                        return;
                    }
                }
                names.typing = None;
                names.adding = false;
                names.note = None;
                let last = names.rows().len().saturating_sub(1);
                self.nav.row = self.nav.row.min(last);
                return;
            }
            Key::Esc => {
                names.typing = None;
                names.adding = false;
                names.note = None;
                return;
            }
            _ => return,
        }
        self.name_check();
    }

    pub(super) fn names_key(&mut self, key: Key) {
        if self.maint.names.typing() {
            return self.names_typed(key);
        }
        if let Some(run) = names_run(self) {
            if run.running() || key != Key::Enter {
                return;
            }
            if run.ok() {
                self.run = None;
                self.back();
                self.read_certs();
            } else if let Some(at) = run.stopped_at() {
                let work = run.work.clone();
                self.begin(work, at);
            }
            return;
        }
        let count = self.maint.names.rows().len();
        if self.maint.names.now.is_none() || self.move_row(key, count) || key != Key::Enter {
            return;
        }
        let Some(at) = self.name_at() else { return };
        let names = &mut self.maint.names;
        let now = names.now.as_ref().expect("a plan");
        match at {
            At::Host => names.typing = Some(now.hostname.clone()),
            At::Other(i) => names.typing = Some(now.sans[i].clone()),
            At::Add if now.sans.len() >= MAX_SANS => {
                self.outcome = Some((false, format!("✗ At most {MAX_SANS} other names.")));
                return;
            }
            At::Add => {
                names.adding = true;
                names.typing = Some(String::new());
            }
            At::Apply => return self.ask_names(),
            At::New => return,
        }
        self.name_check();
    }

    fn ask_names(&mut self) {
        if let Some(why) = super::blocked_by_half_done(self) {
            self.outcome = Some((false, why));
            return;
        }
        // Question and detail fit 40 columns, so the buttons always show.
        self.question = Some((
            Question::Maint {
                text: "Issue new certificates?".into(),
                detail: "for these names".into(),
                then: Then::Names,
            },
            true,
        ));
    }

    pub(super) fn names_yes(&mut self) {
        if let Some(work) = self.maint.names.work() {
            self.begin(work, 0);
        }
    }

    /// A run ended: a finished one says when the new certificate ends,
    /// read from the file again.
    pub(super) fn names_ended(&mut self) {
        let valid = super::certs::valid_until(&self.host);
        if let Some(run) = self.run.as_mut()
            && run.ok()
            && let Kind::Names { done, .. } = &mut run.work.kind
        {
            done.truncate(done.find(" · valid until").unwrap_or(done.len()));
            if let Some(date) = valid {
                done.push_str(&format!(" · valid until {date}"));
            }
        }
    }
}
