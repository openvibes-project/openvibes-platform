//! The Time page's screens: the list and a run's progress or failure.

use platform_host::{Host, StepState};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{At, TimePage};
use crate::tui::{
    app::App,
    kind::Kind,
    maint::failure,
    run::Run,
    status::wrap,
    ui::{
        bar::{Bar, SPINNER},
        frame,
        list::{self, Row},
        logo::Header,
    },
};

pub(super) fn time_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Time))
}

fn row<H: Host>(app: &App<H>, page: &TimePage, at: At, selected: bool) -> Row {
    let t = &app.theme;
    let typed = page.typing.as_ref().filter(|_| selected);
    let plain = |name: &str, value: String| Row::Entry {
        name: vec![Span::raw(name.to_owned())],
        value: vec![Span::styled(value, t.dim())],
    };
    let field = |name: &str, shown: &str, empty: &str| match typed {
        Some(text) => plain(name, format!("{text}█")),
        None if shown.is_empty() => plain(name, empty.into()),
        None => plain(name, shown.to_owned()),
    };
    match at {
        At::Servers => field("NTP servers", &page.servers, "the distribution's own"),
        At::Zone => field("Time zone", &page.zone, "not set"),
        At::Apply => plain("Apply", "restarts the time service".into()),
    }
}

fn help<H: Host>(app: &App<H>, page: &TimePage, at: Option<At>) -> Vec<Line<'static>> {
    let t = &app.theme;
    if page.typing.is_some() {
        return vec![match &page.note {
            Some(Err(why)) => Line::styled(format!("    {why}"), t.red()),
            Some(Ok(ok)) => Line::styled(format!("    {ok}"), t.dim()),
            None => Line::raw(""),
        }];
    }
    let text = match at {
        Some(At::Servers) => {
            "Servers this appliance gets the time from. Agents' clocks matter to alarms."
        }
        Some(At::Zone) => "Used for the times the console shows.",
        Some(At::Apply) => "The time zone is set and chrony restarts.",
        None => "",
    };
    wrap(text, 72, 2)
        .into_iter()
        .map(|l| Line::styled(format!("    {l}"), t.dim()))
        .collect()
}

fn draw_run<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let mut lines = vec![Line::raw("")];
    let bar = if run.running() {
        let spin = SPINNER[app.tick_count % SPINNER.len()];
        lines.push(Line::from(vec![
            Span::styled(format!("    {spin} "), t.teal()),
            Span::raw(format!("{}…", run.work.kind.doing())),
        ]));
        Bar::Busy {
            text: run.work.kind.doing(),
            tick: app.tick_count,
        }
    } else if run.ok() {
        lines.push(Line::styled(
            format!("    ✓ {}{}", run.work.kind.done(), run.took()),
            t.green(),
        ));
        Bar::keys(&[("Enter", "Back")])
    } else {
        let at = run.stopped_at().unwrap_or(0);
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        lines.extend(failure(t, why, "Try again runs it once more."));
        Bar::act(&[("Enter", "Try again")])
    };
    let area = frame::draw(frame, t, head, Some("Time"), &app.bar(bar));
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = time_run(app) {
        return draw_run(frame, head, app, run);
    }
    let t = &app.theme;
    let page = &app.maint.time;
    if page.info.is_none() {
        let area = frame::draw(frame, t, head, Some("Time"), &app.bar(Bar::act(&[])));
        let lines = failure(t, "This host has no timedatectl to manage the clock.", "");
        return frame.render_widget(Paragraph::new(lines), area);
    }
    let rows = page.rows();
    let at = rows.get(app.nav.row).copied();
    let bar = if page.typing.is_some() {
        let label = if at == Some(At::Servers) {
            "NTP servers"
        } else {
            "Time zone"
        };
        Bar::edit(label, "type a value", &[("Enter", "Done")])
    } else if at == Some(At::Apply) {
        Bar::keys(&[("Enter", "Apply")])
    } else {
        Bar::keys(&[("Enter", "Change")])
    };
    let area = frame::draw(frame, t, head, Some("Time"), &app.bar(bar));
    let mut lines = Vec::new();
    if let Some(info) = &page.info {
        lines.push(Line::styled(
            format!("    {}", super::menu_line(info)),
            t.dim(),
        ));
        lines.push(Line::raw(""));
    }
    let help = help(app, page, at);
    let list_rows: Vec<Row> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| row(app, page, *r, i == app.nav.row))
        .collect();
    let height = area
        .height
        .saturating_sub(u16::try_from(lines.len() + help.len()).unwrap_or(u16::MAX));
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(
        t,
        &list_rows,
        app.nav.row,
        &mut scroll,
        height,
        30,
    ));
    app.nav.scroll.set(scroll);
    lines.extend(help);
    frame.render_widget(Paragraph::new(lines), area);
}
