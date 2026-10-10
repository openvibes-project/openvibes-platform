//! The Database and Health screens. State is written as text ("problem",
//! "ok"), so both read without colour.

use platform_host::{Database, Host};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::Line,
    widgets::{Block, Borders, Paragraph},
};

use super::app::App;

const DATABASE_KEYS: &str = "m migrate  n maintenance now  R refresh  Esc back";
const HEALTH_KEYS: &str = "R refresh  Esc back";

fn areas(area: Rect) -> [Rect; 3] {
    Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area)
}

pub fn draw_database<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    let [body, status, keys] = areas(area);
    let lines: Vec<Line> = app
        .database
        .status
        .iter()
        .map(|line| Line::raw(line.as_str()))
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(" database ")),
        body,
    );
    let line = match (&app.database.confirm, &app.message) {
        (Some(Database::Migrate), _) => "Migrate the database schema? y/n".to_owned(),
        (Some(_), _) => "Run maintenance now (partitions, retention)? y/n".to_owned(),
        (None, Some(message)) => message.clone(),
        (None, None) => String::new(),
    };
    frame.render_widget(Paragraph::new(line), status);
    frame.render_widget(Paragraph::new(DATABASE_KEYS), keys);
}

#[allow(dead_code, reason = "Task 7 shows health on Status")]
pub fn draw_health<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    let [body, status, keys] = areas(area);
    let health = &app.database.health;
    let problems = health.iter().filter(|check| check.problem).count();
    let lines: Vec<Line> = health
        .iter()
        .map(|check| {
            let mark = if check.problem { "problem" } else { "ok     " };
            Line::raw(format!("{mark}  {}", check.text))
        })
        .collect();
    let title = match problems {
        0 => " health: no problems ".to_owned(),
        1 => " health: 1 problem ".to_owned(),
        n => format!(" health: {n} problems "),
    };
    frame.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(title)),
        body,
    );
    frame.render_widget(
        Paragraph::new(app.message.clone().unwrap_or_default()),
        status,
    );
    frame.render_widget(Paragraph::new(HEALTH_KEYS), keys);
}
