//! The Configuration screen. Changed fields are marked `*`, absent ones
//! read `(default)`; the check result and prompts are text.

use platform_host::{Host, Service};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState, Wrap},
};

use super::{app::App, configuration::Prompt};

const KEYS: &str = "Tab screens  h/l file  j/k field  Enter edit  u undo  w save  R reload  q quit";
const EDIT_KEYS: &str = "type the value  Enter set  Esc cancel  (empty: the service default)";

fn shown(value: Option<&String>) -> &str {
    value.map_or("(default)", String::as_str)
}

pub fn draw<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    let config = &app.config;
    let service = Service::ALL[config.service];
    let [bar, body, help, check, status, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let names: Vec<String> = Service::ALL
        .iter()
        .map(|s| {
            if *s == service {
                format!("[{}]", s.name())
            } else {
                s.name().to_owned()
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(format!("file: {}", names.join("  "))), bar);
    let block = Block::new()
        .borders(Borders::ALL)
        .title(format!(" {} ", service.path()));
    let prompt = config.prompt;
    let line = match (prompt, &config.form) {
        (Some(Prompt::Save), _) => format!("Write {}? y/n", service.path()),
        (Some(Prompt::Discard(_)), _) => "Discard the unsaved changes? y/n".to_owned(),
        (Some(Prompt::Restart(unit)), _) => format!("Saved. Restart {} now? y/n", unit.name()),
        (None, _) => app.message.clone().unwrap_or_default(),
    };
    frame.render_widget(Paragraph::new(line), status);
    frame.render_widget(
        Paragraph::new(if config.editing.is_some() {
            EDIT_KEYS
        } else {
            KEYS
        }),
        keys,
    );
    let Some(form) = &config.form else {
        frame.render_widget(
            Paragraph::new("Nothing to edit: the file could not be read.").block(block),
            body,
        );
        return;
    };
    let changes = form.changes();
    if prompt == Some(Prompt::Save) {
        let lines: Vec<String> = changes
            .iter()
            .map(|c| {
                format!(
                    "{}: {} → {}",
                    c.key,
                    shown(c.before.as_ref()),
                    shown(c.after.as_ref())
                )
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines.join("\n")).block(block.title(" changes ")),
            body,
        );
        return;
    }
    let width = form
        .fields()
        .iter()
        .map(|f| f.key.len())
        .max()
        .unwrap_or(10);
    let rows = form.fields().iter().enumerate().map(|(index, field)| {
        let marker = if changes.iter().any(|c| c.key == field.key) {
            "*"
        } else {
            " "
        };
        let value = match (&config.editing, index == config.selected) {
            (Some(buffer), true) => {
                // The end of what is typed, so the cursor stays in view.
                let room = usize::from(body.width).saturating_sub(width + 6);
                let skip = buffer.chars().count().saturating_sub(room);
                format!("{}_", buffer.chars().skip(skip).collect::<String>())
            }
            _ => shown(form.get(field.key).as_ref()).to_owned(),
        };
        Row::new([marker.to_owned(), field.key.to_owned(), value])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(u16::try_from(width).unwrap_or(40)),
            Constraint::Min(10),
        ],
    )
    .block(block)
    .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    let mut state = TableState::default().with_selected(Some(config.selected));
    frame.render_stateful_widget(table, body, &mut state);
    let field = form.fields()[config.selected];
    frame.render_widget(Paragraph::new(field.help).wrap(Wrap { trim: true }), help);
    let mut verdict = match &form.validity {
        Ok(()) => "valid".to_owned(),
        Err(error) => format!("invalid: {error}"),
    };
    if !changes.is_empty() {
        verdict.push_str(&format!(" · {} unsaved change(s)", changes.len()));
    }
    frame.render_widget(Paragraph::new(verdict), check);
}
