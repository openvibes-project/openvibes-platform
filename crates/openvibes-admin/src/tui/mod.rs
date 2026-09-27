//! The administration TUI (admin TUI spec §5): `openvibes-admin` with no
//! arguments. Runs as the invoking user; acts on the host only through
//! `platform_host::Host`.

pub mod app;
mod config_view;
mod configuration;
pub mod form;
mod password;
mod services;
mod setup;
#[cfg(test)]
mod setup_tests;
mod setup_view;
#[cfg(test)]
mod tests;

use std::{
    io::IsTerminal,
    process::ExitCode,
    time::{Duration, Instant},
};

use app::{App, Key, Tab};
use platform_host::{Host, native::Native, runner::SystemRunner};
use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Modifier, Style},
    widgets::Paragraph,
};

/// The smallest terminal the screens are laid out for (spec §5).
pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;

pub fn render<H: Host>(frame: &mut Frame, app: &App<H>) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let text = format!(
            "openvibes-admin needs at least {MIN_WIDTH}×{MIN_HEIGHT} (now {}×{}); enlarge the window",
            area.width, area.height
        );
        frame.render_widget(Paragraph::new(text), area);
        return;
    }
    let [title, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    let tabs = match app.tab {
        Tab::Setup => "[Setup]  Services  Configuration",
        Tab::Services => "Setup  [Services]  Configuration",
        Tab::Configuration => "Setup  Services  [Configuration]",
    };
    frame.render_widget(
        Paragraph::new(format!("OpenVIBES administration   {tabs}"))
            .style(Style::new().add_modifier(Modifier::BOLD)),
        title,
    );
    match app.tab {
        Tab::Setup => setup_view::draw(frame, body, app),
        Tab::Services => services::draw(frame, body, app),
        Tab::Configuration => config_view::draw(frame, body, app),
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
                    KeyCode::Char(c) => Key::Char(c),
                    KeyCode::Up => Key::Up,
                    KeyCode::Down => Key::Down,
                    KeyCode::Left => Key::Left,
                    KeyCode::Right => Key::Right,
                    KeyCode::Enter => Key::Enter,
                    KeyCode::Esc => Key::Esc,
                    KeyCode::Backspace => Key::Backspace,
                    KeyCode::Tab | KeyCode::BackTab => Key::Tab,
                    _ => continue,
                };
                app.key(key);
            }
            Ok(false) => {}
            Err(_) => app.quit = true,
        }
        // One Setup step per turn: the screen is redrawn between steps (a
        // step blocks while it runs, e.g. dnf).
        if app.tab == Tab::Setup {
            app.setup_tick();
        }
        if app.tab == Tab::Services && app.confirm.is_none() && refreshed.elapsed() >= REFRESH {
            app.refresh();
            refreshed = Instant::now();
        }
    }
    ExitCode::SUCCESS
}
