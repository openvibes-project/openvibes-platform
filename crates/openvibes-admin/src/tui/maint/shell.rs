//! Maintenance › Shell (shell.py, shellflow.py): the operating system's
//! command line, for experts. Asked on the menu; the password is sudo's
//! (ruling 4), checked by the helper's `shell-open`, which is journalled;
//! then the main loop hands the terminal to the operator's login shell
//! (`Host::shell`) and takes it back when the shell exits.

use chrono::{DateTime, Local};
use platform_host::{Host, StepState};

use super::{Then, row_of};
use crate::tui::{
    app::{App, Question},
    nav::Screen,
    run::{Call, Kind, Run, Work},
    ui::bar::Bar,
};

pub fn work() -> Work {
    Work::new(Kind::Shell, vec![Call::ShellOpen])
}

/// The menu's bar: the spinner while the password is checked, Open the
/// shell on its row.
pub(super) fn menu_bar<H: Host>(app: &App<H>, on_shell: bool) -> Bar {
    if app
        .run
        .as_ref()
        .is_some_and(|r| r.work.kind == Kind::Shell && r.running())
    {
        return Bar::Busy {
            text: format!("{}…", Kind::Shell.doing()),
            tick: app.tick_count,
        };
    }
    Bar::keys(&[("Enter", if on_shell { "Open the shell" } else { "Open" })])
}

impl<H: Host> App<H> {
    pub(super) fn ask_shell(&mut self) {
        self.question = Some((
            Question::Maint {
                text: "Open a shell?".into(),
                detail: "for experts; logged".into(),
                then: Then::Shell,
            },
            true,
        ));
    }

    pub(super) fn shell_yes(&mut self) {
        self.begin(work(), 0);
    }

    /// True once after a shell run ended done: the main loop then hands
    /// the terminal to the shell. A run that stopped (three wrong
    /// passwords, Esc after a wrong one, a helper error) says why on
    /// Maintenance instead. Either way the run is gone: Home has no result
    /// to show for it.
    pub fn take_shell(&mut self) -> bool {
        let ended = self
            .run
            .as_ref()
            .is_some_and(|r| r.work.kind == Kind::Shell && !r.running());
        // A wrong password is asked again: the same run goes on.
        if !ended || self.asking.is_some() {
            return false;
        }
        let run = self.run.take().expect("an ended shell run");
        if self.nav.screen != Screen::Maintenance {
            self.nav.go(Screen::Maintenance);
        }
        self.nav.row = row_of("Shell");
        if run.ok() {
            return true;
        }
        self.outcome = Some((false, why(&run)));
        false
    }

    /// The two lines printed above the shell (shell.py #3), naming the
    /// person the journal names (`SUDO_USER` trusted only as root).
    pub fn shell_header(&self, now: DateTime<Local>) -> [String; 2] {
        header_for(&platform_host::shell::operator(), now)
    }

    /// Runs the shell on the terminal (the caller restored it) until it
    /// exits; a shell that cannot start says so on Maintenance.
    pub fn run_shell(&mut self) {
        if let Err(error) = self.host.shell() {
            let error = error.to_string();
            // Without HostError's "failed: ", like the other pages.
            let why = error.strip_prefix("failed: ").unwrap_or(&error);
            self.outcome = Some((false, format!("The shell could not start: {why}")));
        }
    }
}

/// The two lines printed above the shell for `user` at `now`.
pub fn header_for(user: &str, now: DateTime<Local>) -> [String; 2] {
    [
        format!(
            "OpenVIBES shell · type exit to go back to the menu. Logged as {user}, {}.",
            now.format("%H:%M")
        ),
        "Changes here are yours: Repair can put OpenVIBES' own files right again.".into(),
    ]
}

/// Why a shell run stopped, in the helper's own words.
fn why(run: &Run) -> String {
    let detail = run.states[0].as_ref().map_or("", StepState::detail);
    let detail = detail.strip_prefix("failed: ").unwrap_or(detail);
    format!("{}: {detail}", Kind::Shell.stopped())
}
