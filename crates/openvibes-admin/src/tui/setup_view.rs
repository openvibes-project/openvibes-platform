//! Draws the Setup tab at 80×24: the form, the password prompt, the
//! checklist while running or stopped, and what to keep when finished.

use platform_host::{Host, Step};
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
const RUN_KEYS: &str =
    "r retry failed step  c check  u update  x uninstall  m components  Esc  Tab  q";
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
            vec![Line::raw(format!(
                "Your password (for sudo; used for this run only): {}",
                setup.prompt.masked()
            ))],
            "Enter confirm  Esc cancel",
        ),
        Phase::Running(_) | Phase::Stopped(_) | Phase::Status => (
            checklist(app),
            if matches!(setup.phase, Phase::Stopped(_)) {
                RUN_KEYS
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
            let tick = if setup.components.contains(c) {
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
    let ca = match setup.ca {
        CaMode::Quick => "quick (root created here, key written once)",
        CaMode::Careful => "careful (root stays offline)",
    };
    lines.push(mark(setup.row == CA_ROW, format!("CA:  {ca}")));
    lines.push(mark(
        setup.row == KEY_ROW,
        format!("Root key file:  {}{}", setup.root_key_out, edit(KEY_ROW)),
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
    lines
}

fn checklist<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    app.setup
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
                (Some(state), _) => (state.label().to_owned(), state.detail().to_owned()),
                (None, _) => (String::new(), String::new()),
            };
            Line::raw(format!("{title:<26}{label:<9}{detail}"))
        })
        .collect()
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
    let mut lines = vec![Line::raw(
        "Setup finished. Keep what follows: the password is shown only now.",
    )];
    for (index, step) in Step::ALL.iter().enumerate() {
        if matches!(
            step,
            Step::Ca | Step::Console | Step::Operators | Step::Ready
        ) && let Some(Some(state)) = setup.states.get(index)
        {
            lines.push(Line::raw(format!("{}: {}", step.title(), state.detail())));
        }
    }
    lines
}
