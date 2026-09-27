//! The Services screen: the units, the selected unit's log, and the keys.
//! State is always written as text, so it reads without colour.

use platform_host::{Host, ServiceAction, ServiceStatus};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Row, Table},
};

use super::app::App;

const KEYS: &str = "Tab screens  j/k  s start  t stop  r restart  e/d boot  R refresh  q quit";

fn cells(status: &ServiceStatus) -> [String; 5] {
    let boot = match (status.installed, status.enabled) {
        (false, _) => "not installed",
        (true, true) => "enabled",
        (true, false) => "disabled",
    };
    let ready = match status.ready {
        Some(true) => "ready",
        Some(false) => "not ready",
        None => "-",
    };
    [
        status.unit.label().to_owned(),
        boot.to_owned(),
        if status.installed {
            status.active.clone()
        } else {
            "-".into()
        },
        ready.to_owned(),
        status.since.clone().unwrap_or_default(),
    ]
}

pub fn draw<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    let [table, logs, status, keys] = Layout::vertical([
        Constraint::Length(u16::try_from(app.services.len()).unwrap_or(5) + 3),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let rows = app.services.iter().enumerate().map(|(index, status)| {
        let row = Row::new(cells(status));
        if index == app.selected {
            row.style(Style::new().add_modifier(Modifier::REVERSED))
        } else {
            row
        }
    });
    let header = Row::new(["unit", "boot", "state", "ready", "since"])
        .style(Style::new().add_modifier(Modifier::BOLD));
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(14),
                Constraint::Length(14),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Min(10),
            ],
        )
        .header(header)
        .block(Block::new().borders(Borders::ALL).title(" units ")),
        table,
    );
    let unit = app
        .services
        .get(app.selected)
        .map_or("", |status| status.unit.name());
    let height = usize::from(logs.height.saturating_sub(2));
    let tail = app.logs.len().saturating_sub(height);
    let lines: Vec<Line> = app.logs[tail..]
        .iter()
        .map(|line| Line::raw(line.as_str()))
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::new()
                .borders(Borders::ALL)
                .title(format!(" log: {unit} ")),
        ),
        logs,
    );
    let line = match (&app.boot, &app.confirm, &app.message) {
        (Some((unit, enable, prompt)), _, _) => format!(
            "{} {} at boot: your password: {}",
            if *enable { "Enable" } else { "Disable" },
            unit.name(),
            prompt.masked()
        ),
        (None, Some((unit, action)), _) => format!("{} {}? y/n", capitalised(*action), unit.name()),
        (None, None, Some(message)) => message.clone(),
        (None, None, None) => String::new(),
    };
    frame.render_widget(Paragraph::new(line), status);
    frame.render_widget(Paragraph::new(KEYS), keys);
}

fn capitalised(action: ServiceAction) -> &'static str {
    match action {
        ServiceAction::Start => "Start",
        ServiceAction::Stop => "Stop",
        ServiceAction::Restart => "Restart",
    }
}
