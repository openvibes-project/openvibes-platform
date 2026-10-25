//! Maintenance › Uninstall while it runs and once it ends: the steps, then
//! what stayed or what to do. Split from `uninstall.rs` (size).

use platform_host::{Host, RemoveStep, StepState};
use ratatui::{Frame, text::Line, widgets::Paragraph};

use super::failure;
use crate::tui::{
    app::App,
    run::{Call, Kind, Run},
    status::wrap,
    ui::{bar::Bar, frame, logo::Header, steps},
};

pub(super) fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let Kind::Uninstall { everything } = run.work.kind else {
        return;
    };
    let titles: Vec<String> = RemoveStep::ALL
        .iter()
        .map(|s| s.title().to_owned())
        .collect();
    let bar = match run.current() {
        Some(i) => Bar::Busy {
            text: format!("Step {} of {}: {}", i + 1, titles.len(), titles[i]),
            tick: app.tick_count,
        },
        None if run.ok() => Bar::only(&[("Enter", "Quit")]),
        None => Bar::act(&[("Enter", "Try again")]),
    };
    let area = frame::draw(frame, t, head, Some("Uninstalling"), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    lines.extend(steps::lines(
        t,
        &titles,
        &run.states,
        run.current(),
        app.tick_count,
        6,
    ));
    lines.push(Line::raw(""));
    if run.ok() {
        lines.push(Line::styled(
            format!("    ✓ OpenVIBES is removed from this host{}", run.took()),
            t.green(),
        ));
        // What the helper reported (review I4): Purge's and the last step's
        // notes on what stayed, never a canned outcome.
        let said = |i: usize| {
            run.states
                .get(i)
                .and_then(Option::as_ref)
                .map_or("", StepState::detail)
        };
        let (purge, admin) = (
            said(run.states.len().saturating_sub(2)),
            said(run.states.len().saturating_sub(1)),
        );
        let mut notes: Vec<String> = Vec::new();
        if everything && admin.contains("nothing of OpenVIBES remains") {
            notes.push("Nothing is left behind.".into());
        } else if !everything {
            notes.push("The data stays for a reinstall. PostgreSQL stays installed.".into());
        }
        notes.extend(
            purge
                .split("; ")
                .chain(admin.split("; "))
                .filter(|part| {
                    [
                        "kept:",
                        "PostgreSQL",
                        "the package repository stays",
                        "the site rule key",
                    ]
                    .iter()
                    .any(|start| part.starts_with(start))
                })
                .map(|part| {
                    let mut chars = part.chars();
                    chars.next().map_or_else(String::new, |first| {
                        format!("{}{}.", first.to_uppercase(), chars.as_str())
                    })
                }),
        );
        let backup = run.work.calls.first().and_then(|c| match c {
            Call::Remove(_, args) => args
                .iter()
                .position(|a| a == "--backup")
                .and_then(|i| args.get(i + 1)),
            _ => None,
        });
        let key = app
            .maint
            .plan
            .as_ref()
            .and_then(|p| p.root_key_out.as_ref())
            .filter(|_| everything);
        notes.extend(backup.map(|f| format!("Backup: {f}. Copy it off this host.")));
        notes.extend(key.map(|k| {
            format!(
                "If you kept the root key file {}, it belongs to the old CA: delete it.",
                k.display()
            )
        }));
        for note in notes {
            lines.extend(
                wrap(&note, 72, 2)
                    .into_iter()
                    .map(|l| Line::styled(format!("    {l}"), t.dim())),
            );
        }
    } else if let Some(at) = run.stopped_at() {
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        let todo = if at == 0 {
            "Nothing was removed."
        } else {
            "OpenVIBES is partly removed: Try again finishes it."
        };
        lines.extend(failure(t, why, todo));
    }
    frame.render_widget(Paragraph::new(lines), area);
}
