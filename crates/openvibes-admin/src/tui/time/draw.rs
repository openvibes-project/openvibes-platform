//! The Time page's screens: the list and a run's progress or failure.

use platform_host::Host;
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
        bar::Bar,
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
        At::Servers => {
            let auto = match page.info.as_ref().filter(|i| i.servers.is_empty()) {
                Some(info) => format!("automatic · {}", info.in_use),
                None => "automatic".to_owned(),
            };
            field("NTP servers", &page.servers, &auto)
        }
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
            "Servers this appliance gets the time from; empty is automatic. Agents' clocks matter to alarms."
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

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = time_run(app) {
        return crate::tui::network::draw_run(
            frame,
            head,
            app,
            run,
            "Time",
            "Try again runs it once more.",
        );
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
