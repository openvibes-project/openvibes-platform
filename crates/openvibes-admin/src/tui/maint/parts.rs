//! Maintenance › Optional parts (spec §6; maint2.py, maint2b.py): tick the
//! agent and the assistant, Apply shows what it will do and asks. The
//! plan is saved whole first, then each removed part is stopped, removed
//! and purged (`remove-step`), then the added ones are installed by the
//! repair steps. Removing a part leaves nothing of it behind.

use platform_host::{Host, RemoveStep, Step, StepState};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Then, failure};
use crate::{
    setup::plan::{Component, ModelChoice, Plan, plan_of},
    tui::{
        app::{App, Key, Question},
        run::{Call, Kind, Run, Work, label_states},
        ui::{
            bar::Bar,
            frame,
            list::{self, Row},
            logo::Header,
            steps,
        },
    },
};

const MODEL: &str = "Download the model";

/// The page's choices: what is ticked, from the saved plan.
#[derive(Debug, Default)]
pub struct Parts {
    plan: Option<Plan>,
    error: Option<String>,
    agent: bool,
    assistant: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Part {
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
    fn name(self) -> &'static str {
        self.component().name()
    }
}

/// "the agent", "the agent and the assistant".
fn names(parts: &[Part]) -> String {
    let all: Vec<String> = parts.iter().map(|p| format!("the {}", p.name())).collect();
    all.join(" and ")
}

fn cap(text: &str) -> String {
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

    /// (parts to install, parts to remove).
    fn changes(&self) -> (Vec<Part>, Vec<Part>) {
        let (mut add, mut remove) = (Vec::new(), Vec::new());
        for part in [Part::Agent, Part::Assistant] {
            match (self.ticked(part), self.installed(part)) {
                (true, false) => add.push(part),
                (false, true) => remove.push(part),
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
            .map(|p| ("remove", p))
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
        let mut groups = vec![(
            "Save the choice".to_owned(),
            vec![Call::SetupPlan(plan.args())],
        )];
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
        Some(Work::grouped(
            Kind::Parts {
                what: cap(&doing.join(" and ")),
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

/// The result line, read back from the step titles: "Assistant installed ·
/// ask it in the console".
fn done_line(run: &Run) -> String {
    let mut said: Vec<(Part, bool)> = Vec::new();
    for (title, _) in &run.work.labels {
        let add = if title.starts_with("Install the") {
            true
        } else if title.starts_with("Remove the") {
            false
        } else {
            continue;
        };
        for part in [Part::Agent, Part::Assistant] {
            if title.contains(part.name()) {
                said.push((part, add));
            }
        }
    }
    let heads: Vec<String> = said
        .iter()
        .enumerate()
        .map(|(i, (part, add))| {
            let head = format!(
                "{} {}",
                part.name(),
                if *add { "installed" } else { "removed" }
            );
            if i == 0 { cap(&head) } else { head }
        })
        .collect();
    let tail = match said.as_slice() {
        [(Part::Assistant, true)] => " · ask it in the console",
        [(Part::Agent, true)] => " · this host reports to the console",
        [(_, false)] => " · nothing of it is left on this host",
        _ => "",
    };
    format!("{}{tail}", heads.join(" and "))
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
    Row::Entry {
        name: vec![mark, Span::raw(name)],
        value: vec![Span::styled(value, t.dim())],
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
    let bar = Bar::keys(&[("Space", "Select/deselect"), ("Enter", "Confirm")]);
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

fn draw_run<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let titles: Vec<String> = run.work.labels.iter().map(|(t, _)| t.clone()).collect();
    // The label holding the call running now.
    let running = run
        .current()
        .and_then(|c| run.work.labels.iter().position(|(_, r)| r.contains(&c)));
    // The optional model never stops the run: its own state is a note.
    let states: Vec<Option<StepState>> = label_states(run)
        .into_iter()
        .zip(&titles)
        .map(|(state, title)| match state {
            Some(s) if title == MODEL && !s.finished() => {
                let why = if s.detail().is_empty() {
                    s.label()
                } else {
                    s.detail()
                };
                Some(StepState::Skipped(why.to_owned()))
            }
            other => other,
        })
        .collect();
    let bar = match running {
        Some(i) => Bar::Busy {
            text: format!("Step {} of {}: {}", i + 1, titles.len(), titles[i]),
            tick: app.tick_count,
        },
        None if run.running() => Bar::Busy {
            text: "Finishing…".into(),
            tick: app.tick_count,
        },
        None if run.ok() => Bar::only(&[("Enter", "Back")]),
        None => Bar::act(&[("Enter", "Try again")]),
    };
    let area = frame::draw(frame, t, head, Some(&run.work.kind.doing()), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    lines.extend(steps::lines(
        t,
        &titles,
        &states,
        running,
        app.tick_count,
        10,
    ));
    lines.push(Line::raw(""));
    if run.ok() {
        lines.push(Line::styled(
            format!("    ✓ {} ({})", done_line(run), run.took()),
            t.green(),
        ));
    } else if let Some(at) = run.stopped_at() {
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        let saved = run.work.labels[0].1.contains(&at);
        lines.extend(failure(
            t,
            why,
            if saved {
                "Nothing was changed. Try again saves the choice and goes on."
            } else {
                "The choice is saved. Try again goes on from here."
            },
        ));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_parts(&mut self) {
        self.nav.row = 0;
        // A finished run's result is not news the next time.
        if self
            .run
            .as_ref()
            .is_some_and(|r| !r.running() && matches!(r.work.kind, Kind::Parts { .. }))
        {
            self.run = None;
        }
        let read = self
            .host
            .setup_plan()
            .map_err(|e| e.to_string())
            .and_then(|text| plan_of(&text));
        self.maint.parts = match read {
            Ok(plan) => Parts {
                agent: plan.has(Component::Agent),
                assistant: plan.has(Component::Assistant),
                plan: Some(plan),
                error: None,
            },
            Err(error) => Parts {
                error: Some(format!("The plan cannot be read: {error}")),
                ..Parts::default()
            },
        };
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

    pub(super) fn parts_yes(&mut self) {
        if let Some(work) = self.maint.parts.work() {
            self.begin(work, 0);
        }
    }
}
