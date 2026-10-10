//! The administration TUI (admin TUI spec §5): `openvibes-admin` with no
//! arguments. Runs as the invoking user; acts on the host only through
//! `platform_host::Host`.

pub mod app;
mod config_view;
mod configuration;
mod database;
#[cfg(test)]
mod database_tests;
mod database_view;
pub mod form;
mod home;
mod jobs;
mod maintain;
#[cfg(test)]
mod maintain_tests;
mod maintain_view;
mod nav;
#[cfg(test)]
mod nav_tests;
mod password;
mod service;
#[cfg(test)]
mod service_tests;
mod services_text;
mod setup;
#[cfg(test)]
mod setup_tests;
mod setup_view;
mod status;
#[cfg(test)]
mod status_tests;
#[cfg(test)]
mod tests;
mod ui;
mod work;

use std::{
    io::IsTerminal,
    process::ExitCode,
    time::{Duration, Instant},
};

use app::{App, Key, Tab};
use nav::Screen;
use platform_host::{Host, native::Native, runner::SystemRunner};
use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::Rect,
};

pub fn render<H: Host>(frame: &mut Frame, app: &App<H>) {
    nav::render(frame, app);
}

/// Today's Setup, Configuration and Database screens, under the location line.
pub(super) fn legacy_view<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    match app.tab {
        Tab::Setup => setup_view::draw(frame, area, app),
        Tab::Configuration => config_view::draw(frame, area, app),
        Tab::Database => database_view::draw_database(frame, area, app),
        Tab::Health => {}
    }
}

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
    let mut app = App::new(Native {
        runner: SystemRunner,
    });
    // dnf refreshes its metadata: on another thread, so a slow mirror or
    // no network never holds the first screen.
    let (send, updates) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let packages = Native {
            runner: SystemRunner,
        }
        .packages();
        // The TUI may have quit meanwhile; nobody to tell then.
        let _ = send.send(app::newer_admin(packages));
    });
    app.updates = Some(updates);
    let mut terminal = ratatui::init();
    let _restore = Restore;
    let mut refreshed = Instant::now();
    while !app.quit {
        if let Err(error) = terminal.draw(|frame| render(frame, &app)) {
            drop(_restore);
            eprintln!("openvibes-admin: terminal: {error}");
            return ExitCode::FAILURE;
        }
        let mut pressed = None;
        match event::poll(Duration::from_millis(250)) {
            Ok(true) => {
                let Ok(Event::Key(key)) = event::read() else {
                    continue;
                };
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                let key = match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.quit = true;
                        continue;
                    }
                    // Ctrl+U empties a field; other control chords typed
                    // their letter into it (#78).
                    KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        Key::ClearLine
                    }
                    KeyCode::Char(_) if key.modifiers.contains(KeyModifiers::CONTROL) => continue,
                    KeyCode::Char(c) => Key::Char(c),
                    KeyCode::Up => Key::Up,
                    KeyCode::Down => Key::Down,
                    KeyCode::Left => Key::Left,
                    KeyCode::Right => Key::Right,
                    KeyCode::Enter => Key::Enter,
                    KeyCode::Esc => Key::Esc,
                    KeyCode::Backspace => Key::Backspace,
                    KeyCode::Tab => Key::Tab,
                    KeyCode::BackTab => Key::BackTab,
                    _ => continue,
                };
                pressed = Some(key);
            }
            Ok(false) => {}
            Err(_) => app.quit = true,
        }
        // The key, then one Setup step per turn: the screen is redrawn
        // between steps (a step blocks while it runs, e.g. dnf), and before
        // the first step of a run the key just started.
        app.key_then_tick(pressed);
        app.tick(Instant::now());
        if matches!(app.nav.screen, Screen::Status | Screen::Service(_))
            && app.question.is_none()
            && app.prompt.is_none()
            && refreshed.elapsed() >= REFRESH
        {
            app.refresh();
            refreshed = Instant::now();
        }
    }
    ExitCode::SUCCESS
}
