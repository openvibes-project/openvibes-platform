//! Draws the Uninstall screen.

use platform_host::Host;
use ratatui::{
    style::{Modifier, Style},
    text::Line,
};

use super::{app::App, maintain::UNINSTALL_START_ROW, setup::Phase};

fn row(selected: bool, text: String) -> Line<'static> {
    if selected {
        Line::styled(text, Style::new().add_modifier(Modifier::REVERSED))
    } else {
        Line::raw(text)
    }
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
    lines.push(Line::raw(if setup.everything {
        "PostgreSQL is removed too if Setup installed it and no other database uses it. This program goes last."
    } else {
        "PostgreSQL stays installed. This program goes last."
    }));
    lines
}

pub fn keys(phase: Phase) -> &'static str {
    match phase {
        Phase::Uninstall => "j/k move  space keep/everything  Enter edit/start  Esc back",
        _ => "j/k move  Enter edit/start  Esc back",
    }
}
