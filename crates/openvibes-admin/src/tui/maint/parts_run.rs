//! The run screen of Maintenance › Optional parts: the step rows (the
//! model's as a note), then the result or what failed. Split from
//! `parts.rs` (size).

use std::path::Path;

use platform_host::{Host, StepState};
use ratatui::{Frame, text::Line, widgets::Paragraph};

use super::{
    failure,
    parts::{MODEL, Part, SAVE, cap},
};
use crate::tui::{
    app::App,
    run::{Run, label_states},
    ui::{bar::Bar, frame, logo::Header, steps},
};

/// `(done, total)` bytes from the root helper's progress file (total 0 when
/// unknown); `None` when it is absent or unreadable.
pub(super) fn model_progress(root: &Path) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(root.join("run/openvibes-admin/model-progress")).ok()?;
    let mut numbers = text.split_whitespace().map(|n| n.parse::<u64>().ok());
    Some((numbers.next()??, numbers.next()??))
}

/// `title` and the model download's progress: "Assistant  1.2 of 2.7 GB"
/// (Installing's Assistant row, Optional parts' Download the model).
pub(in crate::tui) fn with_progress(root: &Path, title: &str) -> String {
    format!("{title}  {}", progress_text(model_progress(root)))
}

fn progress_text(progress: Option<(u64, u64)>) -> String {
    let gb = |n: u64| format!("{:.1}", n as f64 / 1e9);
    match progress {
        Some((done, 0)) => format!("{} GB downloaded", gb(done)),
        Some((done, total)) => format!("{} of {} GB", gb(done.min(total)), gb(total)),
        None => "about 2.7 GB".into(),
    }
}

/// The result line (without the time) for these changes: "Assistant
/// installed · ask it in the console".
pub(super) fn done_text(said: &[(Part, bool)]) -> String {
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
    let tail = match said {
        [(Part::Assistant, true)] => " · ask it in the console",
        [(Part::Agent, true)] => " · this host reports to the console",
        [(_, false)] => " · nothing of it is left on this host",
        _ => "",
    };
    format!("{}{tail}", heads.join(" and "))
}

pub(super) fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let titles: Vec<String> = run.work.labels.iter().map(|(t, _)| t.clone()).collect();
    // The label holding the call running now.
    let running = run
        .current()
        .and_then(|c| run.work.labels.iter().position(|(_, r)| r.contains(&c)));
    // The optional model never stops the run: its own row shows its
    // state as a note (label_states keeps it out of the other rows).
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
    let titles: Vec<String> = titles
        .into_iter()
        .map(|t| {
            if t == MODEL && running.is_some_and(|i| run.work.labels[i].0 == MODEL) {
                with_progress(&app.root, &t)
            } else {
                t
            }
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
            format!("    ✓ {} ({})", run.work.kind.done(), run.took()),
            t.green(),
        ));
    } else if let Some(at) = run.stopped_at() {
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        // Finishing a removal saves no choice: it has no Save row.
        let (save, _) = &run.work.labels[0];
        let todo = match (save == SAVE, run.work.labels[0].1.contains(&at)) {
            (true, true) => "Nothing was changed. Try again saves the choice and goes on.",
            (true, false) => "The choice is saved. Try again goes on from here.",
            (false, _) => "Try again goes on from here.",
        };
        lines.extend(failure(t, why, todo));
    }
    frame.render_widget(Paragraph::new(lines), area);
}
