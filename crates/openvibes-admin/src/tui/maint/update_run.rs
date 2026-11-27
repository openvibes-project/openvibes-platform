//! A running or finished Update OpenVIBES (maint1.py; updates.py #9, #10
//! for the appliance's download and signature check first).

use platform_host::{Host, StepState, UpdateStep};
use ratatui::{Frame, text::Line, widgets::Paragraph};

use super::{failure, release, update::STEPS};
use crate::tui::{
    app::App,
    run::{Kind, Run},
    ui::{bar::Bar, frame, logo::Header, steps},
};

/// What to do after a stop, by the step it stopped at (counted in STEPS,
/// after the appliance's download and its check).
fn after(run: &Run, skip: usize) -> String {
    let pre = release::fetched(run);
    let stopped = run.stopped_at().unwrap_or(0);
    if stopped < pre {
        return "Nothing was changed: the services keep running. Try again.".into();
    }
    let at = stopped - pre + skip;
    match (at, run.rescued(0)) {
        (0, _) => "The services keep running; nothing was changed.".into(),
        // Finishing: no rescue; the old schema must not meet new packages.
        (1 | 2, _) if skip == 1 => "The services stay stopped until the update is finished: \
                                     Try again."
            .into(),
        // Stopped at Stop services: no package was touched.
        (1, _) if (0..2).all(|j| run.rescued(j).is_some_and(StepState::finished)) => {
            "The services are started again; nothing was updated: Try again.".into()
        }
        (2, _) if (0..2).all(|j| run.rescued(j).is_some_and(StepState::finished)) => {
            "The services are started again; the packages may be partly updated: Try again.".into()
        }
        (1 | 2, _) if (0..2).all(|j| run.rescued(j).is_some()) => {
            let why = (0..2)
                .filter_map(|j| run.rescued(j))
                .find(|s| !s.finished())
                .map_or("", StepState::detail);
            format!("The services could not be started again ({why}): see Status.")
        }
        (1 | 2, _) if run.running() => "The services are being started again…".into(),
        (1 | 2, _) => "Nothing more was run: see Status for the services.".into(),
        (3, _) => "The packages are new but the database is not yet: Try again finishes it \
                   (it also puts PostgreSQL back if it is missing). \
                   The services stay stopped until then."
            .into(),
        (4, _) => "Some services did not start: see Status, then Try again.".into(),
        _ => "Everything is updated, but a service is not ready yet: see Status.".into(),
    }
}

/// Where Try again starts (a call index): from Stop when the rescue
/// started the services again, else the step that stopped; a download or
/// check that stopped starts again (the download goes on where it was).
pub(super) fn retry_from(run: &Run, skip: usize) -> usize {
    let pre = release::fetched(run);
    match run.stopped_at() {
        None => 0,
        Some(at) if at < pre => 0,
        Some(at) => match at - pre + skip {
            0 => pre,
            // Services stopped again first, unless finishing (no rescue ran).
            1 | 2 if skip == 0 => pre + 1,
            at => at - skip + pre,
        },
    }
}

/// Update's own steps skipped (finishing a half-done update starts at Stop).
pub(super) fn skipped(run: &Run) -> usize {
    UpdateStep::ALL.len() - (run.work.calls.len() - release::fetched(run))
}

pub(super) fn draw_run<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let Kind::Update { to, .. } = &run.work.kind else {
        return;
    };
    let skip = skipped(run);
    let pre = release::fetched(run);
    let titles: Vec<String> = release::FETCH_STEPS[..pre]
        .iter()
        .chain(&STEPS[skip..])
        .map(|s| (*s).to_owned())
        .collect();
    let open = format!("Open {to}");
    let bar = match run.current() {
        Some(i) => Bar::Busy {
            text: format!("Step {} of {}: {}", i + 1, titles.len(), titles[i]),
            tick: app.tick_count,
        },
        None if run.running() => Bar::Busy {
            text: "Starting the services again…".into(),
            tick: app.tick_count,
        },
        None if run.ok() => Bar::only(&[("Enter", open.as_str())]),
        None => Bar::act(&[("Enter", "Try again")]),
    };
    let area = frame::draw(frame, t, head, Some(&run.work.kind.doing()), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    lines.extend(steps::lines(
        t,
        &titles,
        &run.states,
        run.current(),
        app.tick_count,
        // Every step while it runs (updates.py #9); folded to six after a
        // stop, so the reason and what to do fit under them.
        if run.stopped_at().is_some() { 6 } else { 8 },
    ));
    lines.push(Line::raw(""));
    if run.ok() {
        lines.push(Line::styled(
            format!(
                "    ✓ {} · everything is ready{}",
                run.work.kind.done(),
                run.took()
            ),
            t.green(),
        ));
    } else if let Some(at) = run.stopped_at() {
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        lines.extend(failure(t, why, &after(run, skip)));
    }
    frame.render_widget(Paragraph::new(lines), area);
}
