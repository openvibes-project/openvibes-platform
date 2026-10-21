//! Maintenance › Optional parts (spec §6; maint2.py, maint2b.py): tick the
//! agent and the assistant, Apply shows what it will do and asks. The
//! plan is saved whole first, then each removed part is stopped, removed
//! and purged (`remove-step`), then the added ones are installed by the
//! repair steps. Removing a part leaves nothing of it behind; a removal
//! that stopped half way shows as "removal not finished", and Apply
//! finishes it.

use platform_host::{Host, RemoveStep, Step};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    Then, cannot_ask, failure,
    parts_run::{done_text, draw as draw_run},
    read_plan,
};
use crate::{
    setup::plan::{Component, ModelChoice, Plan},
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

pub(super) const MODEL: &str = "Download the model";
pub(super) const SAVE: &str = "Save the choice";

/// The page's choices: what is ticked, from the saved plan.
#[derive(Debug, Default)]
pub struct Parts {
    plan: Option<Plan>,
    error: Option<String>,
    agent: bool,
    assistant: bool,
    /// Not in the plan, but its package or data folder is still here: a
    /// removal that did not finish.
    leftover: Vec<Part>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Part {
    Agent,
    Assistant,
}

impl Part {
    fn component(self) -> Component {
        match self {
            Part::Agent => Component::Agent,
            Part::Assistant => Component::Assistant,
        }
    }
    pub(super) fn name(self) -> &'static str {
        self.component().name()
    }
    /// Its data folder, under the root.
    fn data(self) -> &'static str {
        match self {
            Part::Agent => "var/lib/openvibes-agent",
            Part::Assistant => "var/lib/openvibes-llm",
        }
    }
}

/// "the agent", "the agent and the assistant".
fn names(parts: &[Part]) -> String {
    let all: Vec<String> = parts.iter().map(|p| format!("the {}", p.name())).collect();
    all.join(" and ")
}

pub(super) fn cap(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

impl Parts {
    fn ticked(&self, part: Part) -> bool {
        match part {
            Part::Agent => self.agent,
            Part::Assistant => self.assistant,
        }
    }

    fn installed(&self, part: Part) -> bool {
        self.plan.as_ref().is_some_and(|p| p.has(part.component()))
    }

    /// Out of the plan, unticked, and something of it is still here.
    fn finishing(&self, part: Part) -> bool {
        !self.ticked(part) && !self.installed(part) && self.leftover.contains(&part)
    }

    /// (parts to install, parts to remove or to finish removing).
    fn changes(&self) -> (Vec<Part>, Vec<Part>) {
        let (mut add, mut remove) = (Vec::new(), Vec::new());
        for part in [Part::Agent, Part::Assistant] {
            match (self.ticked(part), self.installed(part)) {
                (true, false) => add.push(part),
                (false, true) => remove.push(part),
                _ if self.finishing(part) => remove.push(part),
                _ => {}
            }
        }
        (add, remove)
    }

    /// The Apply row's value.
    fn says(&self) -> String {
        let (add, remove) = self.changes();
        let said: Vec<String> = remove
            .iter()
            .map(|p| {
                let verb = if self.finishing(*p) {
                    "finish removing"
                } else {
                    "remove"
                };
                (verb, p)
            })
            .chain(add.iter().map(|p| ("install", p)))
            .map(|(verb, p)| format!("{verb} the {}", p.name()))
            .collect();
        if said.is_empty() {
            "nothing changed yet".into()
        } else {
            said.join(" and ")
        }
    }

    /// The saved plan with the ticks applied; the model is fetched when
    /// the assistant is added.
    fn edited(&self) -> Option<Plan> {
        let mut plan = self.plan.clone()?;
        let (add, remove) = self.changes();
        plan.components
            .retain(|c| !remove.iter().any(|p| p.component() == *c));
        plan.components.extend(add.iter().map(|p| p.component()));
        if add.contains(&Part::Assistant) {
            plan.model = ModelChoice::Fetch;
        }
        Some(plan)
    }

    /// One row per call group, in the real order of the work.
    fn work(&self) -> Option<Work> {
        let plan = self.edited()?;
        let (add, remove) = self.changes();
        // Only finishing a removal: the plan is already without it.
        let mut groups = Vec::new();
        if self.plan.as_ref() != Some(&plan) {
            groups.push((SAVE.to_owned(), vec![Call::SetupPlan(plan.args())]));
        }
        if !remove.is_empty() {
            let args = vec![
                "--components".to_owned(),
                remove
                    .iter()
                    .map(|p| p.name())
                    .collect::<Vec<_>>()
                    .join(","),
            ];
            let who = names(&remove);
            let calls =
                |steps: [RemoveStep; 2]| steps.map(|s| Call::Remove(s, args.clone())).to_vec();
            groups.push((
                format!("Stop {who}"),
                calls([RemoveStep::Backup, RemoveStep::Stop]),
            ));
            groups.push((
                format!("Remove {who}"),
                calls([RemoveStep::Firewall, RemoveStep::Packages]),
            ));
            groups.push((
                "Remove its data".to_owned(),
                calls([RemoveStep::Purge, RemoveStep::Admin]),
            ));
        }
        let model = add.contains(&Part::Assistant);
        if !add.is_empty() {
            let install = Step::ALL.iter().take_while(|s| **s != Step::Ready);
            groups.push((
                format!("Install {}", names(&add)),
                install.map(|s| Call::Repair(*s)).collect(),
            ));
            if model {
                groups.push((MODEL.to_owned(), vec![Call::Repair(Step::AssistantModel)]));
            }
        }
        let rest: Vec<Step> = if add.is_empty() {
            Step::ALL.to_vec()
        } else if model {
            vec![Step::Ready]
        } else {
            vec![Step::Ready, Step::AssistantModel]
        };
        let mut calls: Vec<Call> = rest.into_iter().map(Call::Repair).collect();
        calls.push(Call::Status);
        groups.push(("Ready".to_owned(), calls));
        let mut doing = Vec::new();
        if !add.is_empty() {
            doing.push(format!("installing {}", names(&add)));
        }
        if !remove.is_empty() {
            doing.push(format!("removing {}", names(&remove)));
        }
        let said: Vec<(Part, bool)> = remove
            .iter()
            .map(|p| (*p, false))
            .chain(add.iter().map(|p| (*p, true)))
            .collect();
        Some(Work::grouped(
            Kind::Parts {
                what: cap(&doing.join(" and ")),
                done: done_text(&said),
            },
            groups,
        ))
    }
}

fn parts_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Parts { .. }))
}

fn row<H: Host>(app: &App<H>, part: Part) -> Row {
    let t = &app.theme;
    let mark = if app.maint.parts.ticked(part) {
        Span::styled("[x]", t.green())
    } else {
        Span::raw("[ ]")
    };
    let (name, value) = match part {
        Part::Agent => (" Agent on this host", "watch this host too"),
        Part::Assistant => (" Assistant", "local AI helper · 2.7 GB download"),
    };
    let value = if app.maint.parts.finishing(part) {
        Span::styled("removal not finished", t.yellow())
    } else {
        Span::styled(value, t.dim())
    };
    Row::Entry {
        name: vec![mark, Span::raw(name)],
        value: vec![value],
    }
}

fn help<H: Host>(app: &App<H>) -> Line<'static> {
    let parts = &app.maint.parts;
    let text = match app.nav.row {
        row @ (0 | 1) => {
            let part = if row == 0 {
                Part::Agent
            } else {
                Part::Assistant
            };
            match (parts.installed(part), parts.ticked(part), part) {
                _ if parts.finishing(part) => format!(
                    "A removal of the {} stopped half way: Apply finishes it.",
                    part.name()
                ),
                (true, false, _) => format!(
                    "Removing the {} also removes its data from this host.",
                    part.name()
                ),
                (_, _, Part::Agent) => {
                    "The agent reports this host's own findings and alarms.".into()
                }
                _ => "Answers questions about your findings, on this host, no cloud. Needs 4 GB."
                    .into(),
            }
        }
        _ => "Installs or removes what you changed above.".into(),
    };
    Line::styled(format!("    {text}"), app.theme.dim())
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = parts_run(app) {
        return draw_run(frame, head, app, run);
    }
    let t = &app.theme;
    let parts = &app.maint.parts;
    let bar = if parts.error.is_some() {
        Bar::act(&[])
    } else {
        Bar::keys(&[("Space", "Select/deselect"), ("Enter", "Confirm")])
    };
    let area = frame::draw(frame, t, head, Some("Optional parts"), &app.bar(bar));
    let mut lines = Vec::new();
    if let Some(error) = &parts.error {
        lines.extend(failure(t, error, "Nothing was changed."));
        return frame.render_widget(Paragraph::new(lines), area);
    }
    let rows = vec![
        row(app, Part::Agent),
        row(app, Part::Assistant),
        Row::entry("Apply", &parts.says()),
    ];
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, 7, 26));
    app.nav.scroll.set(scroll);
    lines.push(help(app));
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_parts(&mut self) {
        self.nav.row = 0;
        // A successful run's result is not news the next time; a failed one
        // stays, with its Try again.
        if self
            .run
            .as_ref()
            .is_some_and(|r| r.ok() && matches!(r.work.kind, Kind::Parts { .. }))
        {
            self.run = None;
        }
        self.maint.parts = match read_plan(&self.host) {
            Ok(plan) => Parts {
                agent: plan.has(Component::Agent),
                assistant: plan.has(Component::Assistant),
                leftover: [Part::Agent, Part::Assistant]
                    .into_iter()
                    .filter(|p| !plan.has(p.component()) && self.left_behind(*p))
                    .collect(),
                plan: Some(plan),
                error: None,
            },
            Err(error) => Parts {
                error: Some(error),
                ..Parts::default()
            },
        };
    }

    /// Something of `part` is still on this host, seen without sudo: one
    /// of its packages in the list Update reads, or its data folder.
    fn left_behind(&self, part: Part) -> bool {
        let names = part.component().packages();
        let package = matches!(&self.packages,
            Some(Ok(list)) if list.iter().any(|p| names.contains(&p.name.as_str())));
        package || self.root.join(part.data()).exists()
    }

    pub(super) fn parts_key(&mut self, key: Key) {
        if let Some(run) = parts_run(self) {
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
        if self.maint.parts.plan.is_none() || self.move_row(key, 3) {
            return;
        }
        let parts = &mut self.maint.parts;
        match (self.nav.row, key) {
            (0, Key::Char(' ')) => parts.agent = !parts.agent,
            (1, Key::Char(' ')) => parts.assistant = !parts.assistant,
            (_, Key::Enter) => self.ask_parts(),
            _ => {}
        }
    }

    fn ask_parts(&mut self) {
        let (add, remove) = self.maint.parts.changes();
        if add.is_empty() && remove.is_empty() {
            return;
        }
        if let Some(why) = cannot_ask(self, self.maint.parts.plan.as_ref()) {
            self.outcome = Some((false, why));
            return;
        }
        // Question and detail fit 40 columns, so the buttons always show.
        let which = |parts: &[Part]| match parts {
            [one] => format!("the {}", one.name()),
            _ => "both parts".to_owned(),
        };
        let (text, detail, yes) = if !remove.is_empty() {
            let detail = if remove.len() == 1 {
                "its data goes too"
            } else {
                "their data goes too"
            };
            // Starts on No: a stray Enter removes nothing.
            (format!("Remove {}?", which(&remove)), detail, false)
        } else if !add.is_empty() {
            let detail = if add.contains(&Part::Assistant) {
                "2.7 GB"
            } else {
                "watch this host too"
            };
            (format!("Install {}?", which(&add)), detail, true)
        } else {
            return;
        };
        self.question = Some((
            Question::Maint {
                text: cap(&text),
                detail: detail.into(),
                then: Then::Parts,
            },
            yes,
        ));
    }

    /// A finished run removed its parts' packages: drop them from the
    /// list read at start (reading it again runs dnf), or the page would
    /// show them as left behind.
    pub(super) fn parts_ended(&mut self) {
        let done = self
            .run
            .as_ref()
            .is_some_and(|r| r.ok() && matches!(r.work.kind, Kind::Parts { .. }));
        let (true, Ok(plan), Some(Ok(list))) =
            (done, read_plan(&self.host), self.packages.as_mut())
        else {
            return;
        };
        let gone: Vec<&str> = [Part::Agent, Part::Assistant]
            .iter()
            .filter(|p| !plan.has(p.component()))
            .flat_map(|p| p.component().packages().iter().copied())
            .collect();
        list.retain(|p| !gone.contains(&p.name.as_str()));
    }

    pub(super) fn parts_yes(&mut self) {
        if let Some(work) = self.maint.parts.work() {
            self.begin(work, 0);
        }
    }
}
