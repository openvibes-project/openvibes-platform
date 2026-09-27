//! The administration TUI (admin TUI spec §5): `openvibes-admin` with no
//! arguments. Runs as the invoking user; acts on the host only through
//! `platform_host::Host`.

pub mod app;
pub mod form;
mod services;
#[cfg(test)]
mod tests;

use std::{
    io::IsTerminal,
    process::ExitCode,
    time::{Duration, Instant},
};

use platform_host::{native::Native, runner::SystemRunner};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

pub use services::render;

/// How often the unit states are reloaded while the screen is open.
const REFRESH: Duration = Duration::from_secs(5);

/// Restores the terminal however the TUI ends (return, error, or panic:
/// `ratatui::init` also installs a panic hook that restores it).
struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

pub fn run() -> ExitCode {
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        eprintln!(
            "openvibes-admin: the administration TUI needs a terminal; run a subcommand instead (see --help)"
        );
        return ExitCode::from(2);
    }
    let mut app = app::App::new(Native {
        runner: SystemRunner,
    });
    let mut terminal = ratatui::init();
    let _restore = Restore;
    let mut refreshed = Instant::now();
    while !app.quit {
        if let Err(error) = terminal.draw(|frame| render(frame, &app)) {
            drop(_restore);
            eprintln!("openvibes-admin: terminal: {error}");
            return ExitCode::FAILURE;
        }
        match event::poll(Duration::from_millis(250)) {
            Ok(true) => {
                if let Ok(Event::Key(key)) = event::read()
                    && key.kind == KeyEventKind::Press
                {
                    match key.code {
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.quit = true;
                        }
                        KeyCode::Down => app.key('j'),
                        KeyCode::Up => app.key('k'),
                        KeyCode::Esc => app.key('n'),
                        KeyCode::Char(c) => app.key(c),
                        _ => {}
                    }
                }
            }
            Ok(false) => {}
            Err(_) => app.quit = true,
        }
        if refreshed.elapsed() >= REFRESH && app.confirm.is_none() {
            app.refresh();
            refreshed = Instant::now();
        }
    }
    ExitCode::SUCCESS
}
