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

fn spawn(argv: &[String]) -> Result<(), HostError> {
    spawn_with(argv, &[])
}

// Shell entry (spec §10.9): the operator's own login shell, on the inherited
// terminal; and the appliance's OS access (#566).
#[allow(clippy::disallowed_types)]
fn spawn_with(argv: &[String], env: &[(&str, &str)]) -> Result<(), HostError> {
    std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .envs(env.iter().copied())
        .status()
        .map(drop)
        .map_err(|error| HostError::Io(format!("{}: {error}", argv[0])))
}

/// The appliance's OS access levels (#566, ruling #554).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    /// Root's view, but nothing can be written, started or stopped.
    ReadOnly,
    /// The signed-in account's own shell (danger).
    User,
    /// Root's shell (bigger danger).
    Root,
}

/// systemd's sandbox for the read-only shell: root's eyes (every file can
/// be read: `CAP_DAC_READ_SEARCH` alone) and no hands. Every file system is
/// read-only (`/tmp` is its own and goes with it), the kernel's settings,
/// modules, clock and cgroups too; no Unix sockets, so no D-Bus (systemctl
/// cannot start or stop) and no sudo; no signals to other processes, no
/// ptrace; no new privileges.
// ponytail: a deny list on top of read-only mounts; an allow list of
// syscalls is the upgrade if a hole shows.
pub const READ_ONLY: [&str; 16] = [
    "ProtectSystem=strict",
    "ProtectHome=read-only",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "NoNewPrivileges=yes",
    "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK",
    "SystemCallFilter=~@debug @mount @reboot @swap @module @raw-io @clock",
    "SystemCallFilter=~kill tkill tgkill pidfd_send_signal rt_sigqueueinfo rt_tgsigqueueinfo",
    "SystemCallErrorNumber=EPERM",
    "LockPersonality=yes",
];

/// The command line of an OS access shell for `user` (who signed in).
/// None of them opens the TUI again (`OPENVIBES_NO_TUI`, which the
/// appliance's profile hook reads).
pub fn access_argv(access: Access, user: &str) -> Result<Vec<String>, HostError> {
    let owned = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
    Ok(match access {
        Access::User => {
            if !valid_user(user) {
                return Err(whose());
            }
            owned(&[Runuser.path(), "-l", "-w", "OPENVIBES_NO_TUI", user])
        }
        Access::Root => owned(&["/bin/bash", "-l"]),
        Access::ReadOnly => {
            let mut argv = owned(&[
                crate::runner::Program::SystemdRun.path(),
                "--pty",
                "--quiet",
                "--wait",
                "--collect",
                "--service-type=exec",
                "--setenv=OPENVIBES_NO_TUI=1",
                "--setenv=HISTFILE=/dev/null",
            ]);
            for property in READ_ONLY {
                argv.extend(["-p".to_owned(), property.to_owned()]);
            }
            argv.extend(owned(&["/bin/bash", "-l"]));
            argv
        }
    })
}

/// Runs an OS access shell on the inherited terminal until it exits.
pub(crate) fn open_access(access: Access) -> Result<(), HostError> {
    let argv = access_argv(access, &operator())?;
    spawn_with(&argv, &[("OPENVIBES_NO_TUI", "1")])
}

#[cfg(test)]
mod access_tests {
    use super::{Access, READ_ONLY, access_argv};

    #[test]
    fn each_level_has_its_own_shell() {
        assert_eq!(
            access_argv(Access::User, "lime").unwrap(),
            ["/usr/sbin/runuser", "-l", "-w", "OPENVIBES_NO_TUI", "lime"]
        );
        assert!(
            access_argv(Access::User, "-r").is_err(),
            "no option as a name"
        );
        assert_eq!(
            access_argv(Access::Root, "lime").unwrap(),
            ["/bin/bash", "-l"]
        );
        let read_only = access_argv(Access::ReadOnly, "lime").unwrap();
        assert_eq!(read_only[0], "/usr/bin/systemd-run");
        assert!(read_only.contains(&"--pty".to_owned()));
        for property in READ_ONLY {
            assert!(read_only.contains(&property.to_owned()), "{property}");
        }
        assert_eq!(read_only[read_only.len() - 2..], ["/bin/bash", "-l"]);
    }
}
