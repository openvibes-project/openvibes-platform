//! Maintenance › Shell (spec §10.9): the operator's own login shell on the
//! inherited terminal, never root's under sudo (ruling 5). The helper verb
//! `shell-open` before it is what sudo checks and the journal records.

use crate::{
    HostError,
    runner::{
        Program::{Getent, Runuser},
        Runner,
    },
};

/// A user name as `useradd` makes them, and not root: at most 32
/// characters, a lowercase letter or `_` first, then lowercase letters,
/// digits, `_`, `-` or `.`. Setup's operator and the shell's both use it.
#[must_use]
pub fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 32
        && user != "root"
        && user.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase()
                || b == b'_'
                || (i > 0 && (b.is_ascii_digit() || b == b'-' || b == b'.'))
        })
}

fn whose() -> HostError {
    HostError::Failed("cannot tell whose shell to open".into())
}

/// The login shell's command line. Under sudo (uid 0 with a `SUDO_USER`
/// other than root) that user's login shell through `runuser -l`, never
/// root's: a malformed name is an error. Otherwise the passwd entry's
/// shell with `-l` (`/bin/sh` without one); root logged in directly, or
/// sudo run by root, gets root's own.
pub fn shell_argv(
    uid: u32,
    sudo_user: Option<&str>,
    passwd_shell: &str,
) -> Result<Vec<String>, HostError> {
    match sudo_user {
        Some(user) if uid == 0 && user != "root" => {
            if !valid_user(user) {
                return Err(whose());
            }
            Ok(vec![Runuser.path().into(), "-l".into(), user.into()])
        }
        _ => {
            let shell = if passwd_shell.is_empty() {
                "/bin/sh"
            } else {
                passwd_shell
            };
            Ok(vec![shell.into(), "-l".into()])
        }
    }
}

/// The person the shell is for, for the journal and the shell's header.
#[must_use]
pub fn operator() -> String {
    operator_of(
        id(1),
        id(0),
        std::env::var("SUDO_USER").ok().as_deref(),
        &std::fs::read_to_string("/etc/passwd").unwrap_or_default(),
    )
}

/// `SUDO_USER` is trusted only as root (anyone can set it before running
/// the TUI) and only when well formed; otherwise the real uid's passwd
/// name, `uid=N` without one, "unknown" without a uid.
#[must_use]
pub fn operator_of(
    euid: Option<u32>,
    ruid: Option<u32>,
    sudo_user: Option<&str>,
    passwd: &str,
) -> String {
    if let Some(user) = sudo_user.filter(|u| euid == Some(0) && valid_user(u)) {
        return user.to_owned();
    }
    let Some(ruid) = ruid else {
        return "unknown".into();
    };
    let uid = ruid.to_string();
    passwd
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            (fields.len() == 7 && fields[2] == uid).then(|| fields[0].to_owned())
        })
        .filter(|name| !name.is_empty() && !name.contains(char::is_whitespace))
        .unwrap_or_else(|| format!("uid={ruid}"))
}

/// The login shell of `uid` in `passwd` lines; `None` when it has none.
fn passwd_shell(passwd: &str, uid: u32) -> Option<String> {
    let uid = uid.to_string();
    passwd.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        (fields.len() == 7 && fields[2] == uid && fields[6].starts_with('/'))
            .then(|| fields[6].to_owned())
    })
}

/// Field `n` of `Uid:` in `/proc/self/status` (0 real, 1 effective; no
/// `unsafe` libc call); `None` when unreadable.
fn id(n: usize) -> Option<u32> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(n)?
        .parse()
        .ok()
}

/// The effective uid.
pub(crate) fn euid() -> Option<u32> {
    id(1)
}

/// Runs the operator's login shell on the inherited terminal until it
/// exits; its exit status is the operator's own (the last command's).
pub(crate) fn open<R: Runner>(runner: &R) -> Result<(), HostError> {
    let uid = euid().ok_or_else(|| HostError::Io("/proc/self/status: no uid".into()))?;
    let sudo_user = std::env::var("SUDO_USER").ok();
    // /etc/passwd is the fallback when getent is missing or fails.
    let entry = |key: &str| {
        runner
            .run(Getent, &["passwd", "--", key])
            .ok()
            .filter(|out| out.status == 0)
            .map(|out| out.stdout)
            .or_else(|| {
                let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
                passwd
                    .lines()
                    .find(|line| {
                        let fields: Vec<&str> = line.split(':').collect();
                        fields.len() == 7 && (fields[0] == key || fields[2] == key)
                    })
                    .map(str::to_owned)
            })
    };
    let argv = match sudo_user.as_deref() {
        // runuser: the operator's own entry, which must exist (it would
        // otherwise flash an error the redraw clears); root's is not read.
        Some(user) if uid == 0 && user != "root" => {
            let argv = shell_argv(uid, Some(user), "")?;
            if entry(user).is_none() {
                return Err(HostError::Failed(format!(
                    "cannot tell whose shell to open: there is no user named {user}"
                )));
            }
            argv
        }
        sudo_user => {
            let shell = entry(&uid.to_string())
                .and_then(|lines| passwd_shell(&lines, uid))
                .unwrap_or_default();
            shell_argv(uid, sudo_user, &shell)?
        }
    };
    spawn(&argv)
}

// Shell entry (spec §10.9): the operator's own login shell, on the inherited terminal
#[allow(clippy::disallowed_types)]
fn spawn(argv: &[String]) -> Result<(), HostError> {
    std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .status()
        .map(drop)
        .map_err(|error| HostError::Io(format!("{}: {error}", argv[0])))
}
