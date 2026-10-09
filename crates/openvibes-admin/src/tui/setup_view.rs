//! Draws the Setup tab at 80×24: the form, the password prompt, the
//! checklist while running or stopped, and what to keep when finished.

use platform_host::{Host, Step, StepState};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};

use super::{
    app::App,
    jobs::Job,
    maintain_view,
    setup::{AGENT_PORTS_ROW, CA_ROW, HOSTNAME_ROW, KEY_ROW, PORT_ROW, Phase, SANS_ROW, START_ROW},
};
use crate::setup::plan::{CaMode, Component};

const FORM_KEYS: &str = "Tab screens  j/k move  space toggle  Enter edit/start  q quit";
/// After a failed step: retry it, or any other action (#73). Fits 80 columns.
const RUN_KEYS: &str = "r retry  c check  u update  x uninstall  m components  p ports  Esc  q";
/// While a step runs, keys wait for it (the loop runs one step per turn).
const RUNNING_KEYS: &str = "Working: keys wait until this step ends";
/// Fits 80 columns.
const DONE_KEYS: &str = "c check  r repair  u update  m components  p ports  x uninstall  Tab  q";

pub fn draw<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    let [body, status, keys] = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let setup = &app.setup;
    let (lines, help): (Vec<Line>, &str) = match setup.phase {
        Phase::Form => (form(app), FORM_KEYS),
        Phase::Password(_) => (
            vec![
                Line::raw(format!(
                    "Your password (for sudo; used for this run only): {}",
                    setup.prompt.masked()
                )),
                Line::raw(""),
                // #92: started with sudo, the TUI never asks.
                Line::styled(
                    "Tired of typing it? Quit (Esc, then q) and start with: sudo openvibes-admin",
                    Style::default().add_modifier(Modifier::DIM),
                ),
            ],
            "Enter confirm  Esc cancel",
        ),
        Phase::Model => (model_prompt(), "Y download  N skip  Esc back"),
        Phase::Running(_) | Phase::Stopped(_) | Phase::Status => (
            checklist(app, usize::from(body.width.saturating_sub(2))),
            if matches!(setup.phase, Phase::Stopped(_)) {
                RUN_KEYS
            } else if matches!(setup.phase, Phase::Running(_)) {
                RUNNING_KEYS
            } else {
                DONE_KEYS
            },
        ),
        Phase::Finished => (finished(app), DONE_KEYS),
        Phase::Update => (
            maintain_view::update_lines(app),
            maintain_view::keys(Phase::Update),
        ),
        Phase::Uninstall => (
            maintain_view::uninstall_lines(app),
            maintain_view::keys(Phase::Uninstall),
        ),
    };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::new().borders(Borders::ALL).title(" setup ")),
        body,
    );
    frame.render_widget(
        Paragraph::new(app.message.clone().unwrap_or_default()),
        status,
    );
    frame.render_widget(Paragraph::new(help), keys);
}

/// The consent for the assistant's 2.5 GB model, with its licence.
fn model_prompt() -> Vec<Line<'static>> {
    let licence =
        crate::model_fetch::pin_or_embedded().map_or_else(|_| String::new(), |pin| pin.license_url);
    vec![
        Line::raw("Download the assistant's model (2.5 GB from Hugging Face)? [Y/n]"),
        Line::raw(format!("Licence: {licence}")),
        Line::raw(""),
        Line::styled(
            "N leaves the assistant off until you turn it on in Setup again.",
            Style::default().add_modifier(Modifier::DIM),
        ),
    ]
}

fn mark(selected: bool, line: String) -> Line<'static> {
    if selected {
        Line::styled(line, Style::new().add_modifier(Modifier::REVERSED))
    } else {
        Line::raw(line)
    }
}

fn form<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    let setup = &app.setup;
    let mut lines: Vec<Line> = Component::ALL
        .iter()
        .enumerate()
        .map(|(row, c)| {
            let tick = if c.always() {
                "•"
            } else if setup.components.contains(c) {
                "x"
            } else {
                " "
            };
            mark(
                setup.row == row,
                format!("[{tick}] {:<13}{}", c.name(), c.about()),
            )
        })
        .collect();
    let edit = |row: usize| {
        if setup.editing && setup.row == row {
            "_"
        } else {
            ""
        }
    };
    lines.push(mark(
        setup.row == HOSTNAME_ROW,
        format!("Hostname:  {}{}", setup.hostname, edit(HOSTNAME_ROW)),
    ));
    lines.push(mark(
        setup.row == SANS_ROW,
        format!(
            "Other names or addresses (comma-separated):  {}{}",
            setup.sans,
            edit(SANS_ROW)
        ),
    ));
    // Changing a set-up host keeps its CA: no first-install choices.
    let ca = match (setup.previous.is_some(), setup.ca) {
        (true, _) => "kept (this host is set up)",
        (false, CaMode::Quick) => "quick (root created here, key written once)",
        (false, CaMode::Careful) => "careful (root stays offline)",
    };
    lines.push(mark(setup.row == CA_ROW, format!("CA:  {ca}")));
    lines.push(mark(
        setup.row == KEY_ROW,
        if setup.previous.is_some() {
            String::new()
        } else {
            format!("Root key file:  {}{}", setup.root_key_out, edit(KEY_ROW))
        },
    ));
    let note = |note: &Option<String>| {
        note.as_ref()
            .map_or_else(String::new, |n| format!("  ({n})"))
    };
    lines.push(mark(
        setup.row == PORT_ROW,
        format!(
            "Console port:  {}{}{}",
            setup.console_port,
            edit(PORT_ROW),
            note(&setup.console_note)
        ),
    ));
    lines.push(mark(
        setup.row == AGENT_PORTS_ROW,
        format!(
            "Agent ports (ingest, distribution):  {}{}{}",
            setup.agent_ports,
            edit(AGENT_PORTS_ROW),
            note(&setup.agent_ports_note)
        ),
    ));
    lines.push(mark(setup.row == START_ROW, "[ Start ]".into()));
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        help(setup),
        Style::default().add_modifier(Modifier::DIM),
    ));
    lines
}

/// What the row under the cursor means (install walkthrough, 2026-10-08:
/// the CA and root key rows were unexplained).
fn help(setup: &super::setup::Setup) -> &'static str {
    match setup.row {
        row if row < Component::ALL.len() => {
            "Space ticks or unticks a component; [•] ones are always installed."
        }
        HOSTNAME_ROW => "The name agents and browsers use to reach this host.",
        SANS_ROW => "More names or IP addresses for its certificate, e.g. 10.0.0.5.",
        CA_ROW if setup.previous.is_some() => "This host keeps the CA it was set up with.",
        CA_ROW => match setup.ca {
            CaMode::Quick => {
                "Quick: the root CA is made here; its key is written once to the file below."
            }
            CaMode::Careful => {
                "Careful: the root key never touches this host. Space switches the mode."
            }
        },
        KEY_ROW => "The file gets the only copy of the root key; move it offline after Setup.",
        PORT_ROW => "Where the web console listens: 443 unless another program has it.",
        AGENT_PORTS_ROW => "Where agents send findings and fetch rules.",
        _ => "Enter installs the ticked components; takes a few minutes.",
    }
}

/// One line per step, cut to `width` so the list never runs off the screen
/// (#78: wrapped details pushed the last steps out of view); the step a run
/// stopped at gets its whole detail under the list.
fn checklist<H: Host>(app: &App<H>, width: usize) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = app
        .setup
        .job
        .titles()
        .into_iter()
        .enumerate()
        .map(|(index, title)| {
            let state = app.setup.states.get(index).and_then(Option::as_ref);
            let (label, detail) = match (state, app.setup.phase) {
                (_, Phase::Running(next)) if next == index => {
                    ("running…".to_owned(), String::new())
                }
                // A generated password waits for the last screen (or the
                // stopped screen, below); other console details show as is.
                (Some(StepState::Done(detail)), _)
                    if Step::ALL.get(index) == Some(&Step::Console)
                        && admin_password(detail).is_some() =>
                {
                    (
                        "done".to_owned(),
                        "admin account ready (password at the end)".to_owned(),
                    )
                }
                (Some(state), _) => (state.label().to_owned(), state.detail().to_owned()),
                (None, _) => (String::new(), String::new()),
            };
            Line::raw(cut(&format!("{title:<26}{label:<9}{detail}"), width))
        })
        .collect();
    if let Phase::Running(next) = app.setup.phase
        && matches!(app.setup.job, Job::Install | Job::Repair)
        && Step::ALL.get(next) == Some(&Step::Packages)
    {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "Installing packages can take a few minutes (dnf downloads them).",
            Style::default().add_modifier(Modifier::DIM),
        ));
    }
    if let Phase::Stopped(at) = app.setup.phase
        && let Some(Some(state)) = app.setup.states.get(at)
    {
        lines.push(Line::raw(""));
        lines.push(Line::raw(state.detail().to_owned()));
        // The password made before the stop is shown now: the run may never
        // reach its last screen.
        if let Some(password) = done(&app.setup.states, Step::Console).and_then(admin_password) {
            lines.push(Line::raw(format!("{:<10}admin / {password}", "Sign in")));
        }
    }
    lines
}

/// `text` in at most `width` characters, ending in "…" when cut.
fn cut(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

fn finished<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    let setup = &app.setup;
    if setup.job != Job::Install {
        // Repair, update, remove: every step's outcome.
        let mut lines = vec![Line::raw("Finished.")];
        for (index, title) in setup.job.titles().into_iter().enumerate() {
            if let Some(Some(state)) = setup.states.get(index) {
                lines.push(Line::raw(format!(
                    "{title}: {} {}",
                    state.label(),
                    state.detail()
                )));
            }
        }
        if setup.job == Job::Remove {
            lines.push(Line::raw("Last step: sudo dnf remove openvibes-admin"));
        }
        return lines;
    }
    install_finished(&setup.states)
}

/// The step's detail when it finished done.
fn done(states: &[Option<StepState>], step: Step) -> Option<&str> {
    let index = Step::ALL.iter().position(|s| *s == step)?;
    match states.get(index)? {
        Some(StepState::Done(detail)) => Some(detail),
        _ => None,
    }
}

/// The admin password a console detail carries (only when Setup generated
/// one: `setup/console.rs`).
fn admin_password(detail: &str) -> Option<&str> {
    between(detail, ", password ", " (")
}

/// `text` between `start` and `end` (to its end when `end` is absent).
fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let rest = &text[text.find(start)? + start.len()..];
    Some(rest.find(end).map_or(rest, |at| &rest[..at]))
}

/// The end of an install run: what to keep, labelled, and what to do next
/// (install walkthrough, 2026-10-08). Values are taken from the step details
/// the helper sends (`setup/console.rs`, `setup/pki.rs`, `setup/base.rs`); a
/// detail in another wording is shown as it is, never dropped.
fn install_finished(states: &[Option<StepState>]) -> Vec<Line<'static>> {
    let dim = Style::default().add_modifier(Modifier::DIM);
    let row = |label: &str, value: Line<'static>| {
        let mut spans = vec![ratatui::text::Span::styled(format!("{label:<10}"), dim)];
        spans.extend(value.spans);
        Line::from(spans)
    };
    let console = done(states, Step::Console);
    let url = console.and_then(|d| d.split(" · ").next().filter(|u| u.starts_with("https://")));
    let password = console.and_then(admin_password);
    let mut lines = vec![Line::raw(if password.is_some() {
        "Setup finished. Write the password down: it is shown only now."
    } else {
        "Setup finished."
    })];
    lines.push(Line::raw(""));
    if let Some(url) = url {
        lines.push(row("Console", Line::raw(url.to_owned())));
    }
    if let Some(password) = password {
        lines.push(row(
            "Sign in",
            Line::from(vec![
                ratatui::text::Span::raw("admin / "),
                ratatui::text::Span::styled(
                    password.to_owned(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
        ));
    }
    if let Some(detail) = done(states, Step::Ca) {
        if let Some(path) = between(detail, "root key saved to ", ": keep it offline") {
            lines.push(row("Root key", Line::raw(path.to_owned())));
            lines.push(row(
                "",
                Line::raw("The only copy. Move it to offline storage, then delete it here."),
            ));
            // What the write added after the path, e.g. that the file is
            // still owned by root (setup/system.rs `write_new`).
            if let Some(note) = between(detail, ": keep it offline", "; root certificate")
                .map(|n| {
                    n.trim()
                        .trim_start_matches(['(', ' '])
                        .trim_end_matches(')')
                })
                .filter(|n| !n.is_empty())
            {
                lines.push(row("", Line::raw(note.to_owned())));
            }
        } else {
            lines.push(row("Root CA", Line::raw(detail.to_owned())));
        }
    }
    lines.push(Line::raw(""));
    let model = Step::ALL
        .iter()
        .position(|s| *s == Step::AssistantModel)
        .and_then(|index| states.get(index)?.as_ref());
    if let Some(StepState::Skipped(detail)) = model
        && detail.starts_with("assistant: off")
    {
        lines.push(Line::raw(detail.clone()));
    }
    if url.is_some() {
        lines.push(Line::raw(if password.is_some() {
            "Next: sign in, change the password, then add hosts under Enrollment."
        } else {
            "Next: sign in, then add hosts under Enrollment."
        }));
    }
    if let Some(user) =
        done(states, Step::Operators).and_then(|d| d.split_once(" added to ").map(|(user, _)| user))
    {
        lines.push(Line::styled(
            format!("{user} can run openvibes-admin without sudo after logging in again."),
            dim,
        ));
    }
    lines
}
