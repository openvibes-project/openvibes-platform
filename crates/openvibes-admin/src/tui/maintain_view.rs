//! Draws the Update and Uninstall screens.

use platform_host::Host;
use ratatui::{
    style::{Modifier, Style},
    text::Line,
};

use super::{
    app::App,
    maintain::{UNINSTALL_START_ROW, UPDATE_START_ROW},
    setup::Phase,
};

fn row(selected: bool, text: String) -> Line<'static> {
    if selected {
        Line::styled(text, Style::new().add_modifier(Modifier::REVERSED))
    } else {
        Line::raw(text)
    }
}

pub fn update_lines<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    let setup = &app.setup;
    let mut lines: Vec<Line> = setup
        .packages
        .iter()
        .map(|p| {
            Line::raw(format!(
                "{:<26}{:<16}{}",
                p.name,
                p.installed,
                p.available
                    .as_deref()
                    .map_or_else(|| "up to date".to_owned(), |v| format!("→ {v}"))
            ))
        })
        .collect();
    lines.push(Line::raw(""));
    let cursor = if setup.editing && setup.row2 == 0 {
        "_"
    } else {
        ""
    };
    lines.push(row(
        setup.row2 == 0,
        format!("Backup first (empty: none):  {}{cursor}", setup.backup),
    ));
    lines.push(row(
        setup.row2 == UPDATE_START_ROW,
        "[ Update ]  services stop, packages upgrade, database migrates, services start".into(),
    ));
    lines
}

pub fn uninstall_lines<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    let setup = &app.setup;
    let mode = if setup.everything {
        "Remove everything: database, CA, site key, configuration and accounts too"
    } else {
        "Keep data: remove the software, keep database, CA and configuration"
    };
    let cursor = |r: usize| {
        if setup.editing && setup.row2 == r {
            "_"
        } else {
            ""
        }
    };
    let mut lines = vec![row(setup.row2 == 0, format!("( space )  {mode}"))];
    if setup.everything {
        lines.push(row(
            setup.row2 == 1,
            format!("Backup first (empty: none):  {}{}", setup.backup, cursor(1)),
        ));
        lines.push(row(
            setup.row2 == 2,
            format!(
                "Type this host's name to confirm:  {}{}",
                setup.confirm,
                cursor(2)
            ),
        ));
    } else {
        lines.push(Line::raw(""));
        lines.push(Line::raw(""));
    }
    lines.push(row(
        setup.row2 == UNINSTALL_START_ROW,
        "[ Uninstall ]".into(),
    ));
    lines.push(Line::raw(
        "PostgreSQL itself stays installed. openvibes-admin is removed last, by you.",
    ));
    lines
}

pub fn keys(phase: Phase) -> &'static str {
    match phase {
        Phase::Uninstall => "j/k move  space keep/everything  Enter edit/start  Esc back",
        _ => "j/k move  Enter edit/start  Esc back",
    }
}
