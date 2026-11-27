//! The appliance's console sign-in (#565, ruling #554; signin.py): agetty
//! runs `openvibes-admin signin` instead of asking `login:`. It checks the
//! account and password through PAM (the `login` service, so faillock
//! locks an account after 3 wrong passwords for 10 minutes), then hands
//! the console to `login -f ACCOUNT`, which opens the session; the
//! profile hook opens Home, and Log out ends the session, so agetty
//! starts this screen again.

use std::{
    ffi::{OsStr, OsString},
    os::unix::process::CommandExt,
    process::ExitCode,
    time::Duration,
};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{Frame, widgets::Paragraph};
use zeroize::Zeroizing;

use super::{
    app::Key,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row, Scroll},
        logo::Header,
        theme::Theme,
    },
};

/// Wrong passwords before pam_faillock locks the account (its default).
const TRIES: u32 = 3;

/// The screen's state: what is typed, the row, what the line says.
#[derive(Default)]
pub struct SignIn {
    pub account: String,
    pub password: Zeroizing<String>,
    /// 0 Account, 1 Password, 2 Sign in.
    pub row: usize,
    /// Wrong passwords in a row for `account`, as this screen saw them.
    // ponytail: counted here, not read from faillock; a restart forgets it.
    failed: (String, u32),
    /// Said in red under the list.
    pub error: Option<String>,
    /// The console and SSH addresses, under the help line.
    pub reach: String,
}

impl SignIn {
    /// A key: true when Enter on Sign in asks for the check.
    pub fn key(&mut self, key: Key) -> bool {
        match (key, self.row) {
            (Key::Up, _) => self.row = self.row.saturating_sub(1),
            (Key::Down | Key::Tab, _) => self.row = (self.row + 1).min(2),
            (Key::Enter, 0 | 1) => self.row += 1,
            (Key::Enter, _) => return !self.account.is_empty(),
            (Key::Backspace, 0) => {
                self.account.pop();
            }
            (Key::Backspace, 1) => {
                self.password.pop();
            }
            (Key::ClearLine, 0) => self.account.clear(),
            (Key::ClearLine, 1) => self.password.clear(),
            // Account names are short and plain; anything else is no account.
            (Key::Char(c), 0) if self.account.len() < 32 && !c.is_control() => {
                self.account.push(c);
            }
            (Key::Char(c), 1) if self.password.len() < 512 && !c.is_control() => {
                self.password.push(c);
            }
            _ => {}
        }
        false
    }

    /// After a wrong password: cleared, back on Password, and said.
    pub fn refused(&mut self) {
        self.password.clear();
        self.row = 1;
        if self.failed.0 != self.account {
            self.failed = (self.account.clone(), 0);
        }
        self.failed.1 += 1;
        let left = TRIES.saturating_sub(self.failed.1);
        self.error = Some(match left {
            0 => "✗ Wrong account or password, or the account is locked for 10 minutes.".into(),
            1 => "✗ Wrong account or password. 1 try left before a 10-minute lock.".into(),
            n => format!("✗ Wrong account or password. {n} tries left before a 10-minute lock."),
        });
    }

    fn help(&self) -> &'static str {
        if self.row == 0 {
            "The account made when the appliance was installed, or another one."
        } else {
            "Its password. Three wrong ones lock the account for 10 minutes."
        }
    }
}

/// "The console: https://HOST · SSH: ACCOUNT@ADDRESS", either part when known.
pub fn reach(console: Option<String>, ssh: Option<String>) -> String {
    let parts: Vec<String> = [
        console.map(|url| format!("The console: {url}")),
        ssh.map(|at| format!("SSH: {at}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    parts.join(" · ")
}

pub fn draw(frame: &mut Frame, theme: &Theme, hostname: &str, screen: &SignIn) {
    if frame::too_small(frame) {
        return;
    }
    let location = format!("{hostname} · Sign in");
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let head = Header {
        location: &location,
        version: &version,
        update: None,
    };
    let next = if screen.row == 2 { "Sign in" } else { "Next" };
    let bar = Bar::only(&[(theme.up_down(), "Move"), ("Enter", next)]);
    let area = frame::draw(frame, theme, &head, Some("Sign in to this appliance"), &bar);
    let typed = |text: String, row: usize| {
        if screen.row == row {
            format!("{text}█")
        } else {
            text
        }
    };
    let rows = [
        Row::entry("Account", &typed(screen.account.clone(), 0)),
        Row::entry(
            "Password",
            &typed("•".repeat(screen.password.chars().count()), 1),
        ),
        Row::entry("Sign in", "opens the menu"),
    ];
    let mut lines = list::lines(theme, &rows, screen.row, &mut Scroll::default(), 7, 18);
    lines.push("".into());
    lines.push(match &screen.error {
        Some(error) => ratatui::text::Line::styled(format!("    {error}"), theme.red()),
        None => ratatui::text::Line::styled(format!("    {}", screen.help()), theme.dim()),
    });
    lines.push("".into());
    lines.push(ratatui::text::Line::styled(
        format!("    {}", screen.reach),
        theme.dim(),
    ));
    frame.render_widget(Paragraph::new(lines), area);
}

/// PAM's questions: the account for a plain prompt, the password for a
/// masked one.
struct Answers<'a> {
    account: &'a str,
    password: &'a str,
}

impl nonstick::ConversationAdapter for Answers<'_> {
    fn prompt(&self, _: impl AsRef<OsStr>) -> nonstick::Result<OsString> {
        Ok(self.account.into())
    }
    fn masked_prompt(&self, _: impl AsRef<OsStr>) -> nonstick::Result<OsString> {
        Ok(self.password.into())
    }
    fn error_msg(&self, _: impl AsRef<OsStr>) {}
    fn info_msg(&self, _: impl AsRef<OsStr>) {}
}

/// Whether PAM's `login` service lets `account` in with `password`.
fn accepted(account: &str, password: &str) -> bool {
    use nonstick::{AuthnFlags, Transaction, TransactionBuilder};
    let answers = Answers { account, password };
    TransactionBuilder::new_with_service("login")
        .username(account)
        .build(nonstick::ConversationAdapter::into_conversation(answers))
        .and_then(|mut pam| {
            pam.authenticate(AuthnFlags::empty())?;
            pam.account_management(AuthnFlags::empty())
        })
        .is_ok()
}

/// The first global IPv4 address, from `ip -4 -o addr`.
fn address() -> Option<String> {
    use platform_host::runner::{Program::Ip, Runner, SystemRunner};
    let out = SystemRunner
        .run(Ip, &["-4", "-o", "addr", "show", "scope", "global"])
        .ok()?;
    out.stdout
        .split_whitespace()
        .skip_while(|word| *word != "inet")
        .nth(1)
        .and_then(|cidr| cidr.split('/').next())
        .map(str::to_owned)
}

/// Where the console and SSH are, from the plan and the first account.
fn reach_here() -> String {
    let plan = crate::setup::plan::Plan::load(std::path::Path::new("/")).ok();
    let console = plan.as_ref().map(|plan| match plan.console_port {
        443 => format!("https://{}", plan.hostname),
        port => format!("https://{}:{port}", plan.hostname),
    });
    let first = std::fs::read_to_string(format!("/{}", platform_host::ssh::FIRST_ACCOUNT))
        .ok()
        .map(|name| name.trim().to_owned());
    let port = plan.map_or(22, |plan| plan.ssh_port);
    let ssh = address().map(|ip| {
        let at = first.map_or(ip.clone(), |name| format!("{name}@{ip}"));
        if port == 22 {
            at
        } else {
            format!("{at} port {port}")
        }
    });
    reach(console, ssh)
}

fn key_of(code: KeyCode, modifiers: KeyModifiers) -> Option<Key> {
    Some(match code {
        KeyCode::Char('u') if modifiers.contains(KeyModifiers::CONTROL) => Key::ClearLine,
        KeyCode::Char(_) if modifiers.contains(KeyModifiers::CONTROL) => return None,
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Tab => Key::Tab,
        KeyCode::Enter => Key::Enter,
        KeyCode::Backspace => Key::Backspace,
        _ => return None,
    })
}

/// `openvibes-admin signin`: the screen until an account signs in, then
/// `login -f` in its place.
pub fn run() -> ExitCode {
    let theme = Theme::from_env();
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_lowercase())
        .unwrap_or_default();
    let mut screen = SignIn {
        reach: reach_here(),
        ..SignIn::default()
    };
    let mut terminal = ratatui::init();
    // The Linux console has no alternate screen (#549).
    let _ = terminal.clear();
    loop {
        if terminal
            .draw(|frame| draw(frame, &theme, &hostname, &screen))
            .is_err()
        {
            ratatui::restore();
            return ExitCode::FAILURE;
        }
        if !event::poll(Duration::from_secs(60)).unwrap_or(false) {
            continue;
        }
        let Ok(Event::Key(key)) = event::read() else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        let Some(key) = key_of(key.code, key.modifiers) else {
            continue;
        };
        if !screen.key(key) {
            continue;
        }
        // A valid name only: it becomes login's argument (no `-f -r`).
        if platform_host::shell::valid_user(&screen.account)
            && accepted(&screen.account, &screen.password)
        {
            break;
        }
        screen.refused();
    }
    ratatui::restore();
    let _ = terminal.clear();
    let error = login(&screen.account);
    eprintln!("openvibes-admin: /usr/bin/login: {error}");
    ExitCode::FAILURE
}

/// `login -f ACCOUNT` in this process's place; returns only on failure.
/// login opens the session (utmp, limits, the account's shell); only root
/// may skip its own password question, which PAM answered already.
// One of the places the platform starts a process (clippy.toml): a fixed
// path, no shell, and an account name `shell::valid_user` passed.
#[allow(clippy::disallowed_types)]
fn login(account: &str) -> std::io::Error {
    std::process::Command::new("/usr/bin/login")
        .args(["-f", account])
        .exec()
}

#[cfg(test)]
#[path = "signin_tests.rs"]
mod tests;
