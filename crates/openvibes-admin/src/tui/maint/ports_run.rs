//! The run screen of Maintenance › Ports and addresses and › Certificates ›
//! Names: the step rows, then the result or what failed.

use platform_host::{Host, StepState};
use ratatui::{Frame, text::Line, widgets::Paragraph};

use super::failure;
use crate::tui::{
    app::App,
    run::{Kind, Run, label_states},
    ui::{bar::Bar, frame, logo::Header, steps},
};

pub(super) fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let titles: Vec<String> = run.work.labels.iter().map(|(t, _)| t.clone()).collect();
    let running = run
        .current()
        .and_then(|c| run.work.labels.iter().position(|(_, r)| r.contains(&c)));
    let states: Vec<Option<StepState>> = label_states(run);
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
            format!("    ✓ {}{}", run.work.kind.done(), run.took()),
            t.green(),
        ));
    } else if let Some(at) = run.stopped_at() {
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        let saved = run.work.labels[0].1.contains(&at);
        let (unsaved, kept) = match run.work.kind {
            Kind::Names { .. } => (
                "Nothing was changed. Try again saves the names and goes on.",
                "The names are saved. Try again goes on from here.",
            ),
            _ => (
                "Nothing was changed. Try again saves the ports and goes on.",
                "The ports are saved. Try again goes on from here.",
            ),
        };
        lines.extend(failure(t, why, if saved { unsaved } else { kept }));
    }
    frame.render_widget(Paragraph::new(lines), area);
}
