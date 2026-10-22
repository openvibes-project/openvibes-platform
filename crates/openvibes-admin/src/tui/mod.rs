//! The administration TUI (admin TUI spec §5): `openvibes-admin` with no
//! arguments. Runs as the invoking user; acts on the host only through
//! `platform_host::Host`.

pub mod app;
mod config_view;
mod configuration;
mod database;
#[cfg(test)]
mod database_tests;
pub mod form;
mod home;
mod maint;
mod nav;
#[cfg(test)]
mod nav_tests;
mod password;
mod run;
mod run_app;
#[cfg(test)]
mod run_tests;
#[cfg(test)]
mod script_host;
mod service;
#[cfg(test)]
mod service_tests;
mod services_text;
mod setup;
#[cfg(test)]
mod setup_done_tests;
mod setup_form;
#[cfg(test)]
mod setup_form_tests;
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

/// Today's Setup and Configuration screens, under the location line.
pub(super) fn legacy_view<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    match app.tab {
        Tab::Setup => setup_view::draw(frame, area, app),
        Tab::Configuration => config_view::draw(frame, area, app),
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
    let mut app = App::lazy(Native {
        runner: SystemRunner,
    });
    // dnf refreshes its metadata: on another thread, so a slow mirror or
    // no network never holds the first screen.
    let (send, updates) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The TUI may have quit meanwhile; nobody to tell then.
        let _ = send.send(
            Native {
                runner: SystemRunner,
            }
            .packages(),
        );
    });
    app.updates = Some(updates);
    // The health probes run on another thread too (certificates, feeds,
    // disk): Home's status line counts them once they arrive.
    let (send, health) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = send.send(database::health_checks(&Native {
            runner: SystemRunner,
        }));
    });
    app.health = Some(health);
    // Helper steps run on their own thread with their own host: the
    // screen keeps drawing while dnf or a backup takes minutes.
    app.worker = Some(Box::new(|work, from, secret| {
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let host = Native {
                runner: SystemRunner,
            };
            run::work_through(&host, &work, from, &secret, |p| send.send(p).is_ok());
        });
        receive
    }));
    // The backup folder's probe file and df can hang on a dead mount: they
    // run on their own thread, and the page gives up waiting.
    app.checker = Some(Box::new(|text| {
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let host = Native {
                runner: SystemRunner,
            };
            let _ = send.send(maint::backup::check_folder(&host, &text));
        });
        receive
    }));
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
                        app.interrupt();
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
        if matches!(
            app.nav.screen,
            Screen::Home | Screen::Status | Screen::Service(_)
        ) && app.question.is_none()
            && app.prompt.is_none()
            && refreshed.elapsed() >= REFRESH
        {
            app.refresh();
            refreshed = Instant::now();
        }
        if app.take_shell() {
            // The operator's login shell gets the terminal until it exits.
            ratatui::restore();
            let [first, second] = app.shell_header(chrono::Local::now());
            if app.theme.color {
                println!("\x1b[1;38;2;54;185;224m{first}\x1b[0m\n\x1b[2m{second}\x1b[0m");
            } else {
                println!("{first}\n{second}");
            }
            app.run_shell();
            terminal = ratatui::init();
            // Whatever the shell left on screen is drawn over in full.
            let _ = terminal.clear();
        }
        if app.reopen {
            ratatui::restore();
            let error = reopen();
            // Only reached when exec failed.
            terminal = ratatui::init();
            app.reopen = false;
            app.outcome = Some((false, format!("could not start the new version: {error}")));
        }
    }
    ExitCode::SUCCESS
}

/// Replaces this process with the updated menu (`exec`); returns only on failure.
// One of the places the platform starts a process (clippy.toml): a fixed
// path, no arguments, no shell; the environment (and sudo's) is kept.
#[allow(clippy::disallowed_types)]
fn reopen() -> std::io::Error {
    use std::os::unix::process::CommandExt;
    std::process::Command::new("/usr/bin/openvibes-admin").exec()
}
