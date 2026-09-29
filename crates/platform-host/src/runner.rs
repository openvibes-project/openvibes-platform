//! Every command the host backend runs goes through a [`Runner`]: one of a
//! closed set of [`Program`]s and an argument vector, never a shell string.
//! The set is closed so the clippy exception on [`SystemRunner`] covers only
//! these programs, not any command a caller might pass.

/// The programs the host backend may run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Program {
    /// Unit states and lifecycle (polkit decides).
    Systemctl,
    /// The root helper, non-interactively (`sudo -n`).
    Sudo,
    /// Journal entries for operator actions.
    Logger,
    /// Readiness probes on loopback.
    Curl,
    /// Packages (Setup, as root).
    Dnf,
    /// Package queries.
    Rpm,
    /// Commands as a service account (Setup, as root).
    Runuser,
    /// PostgreSQL's first initialisation.
    PostgresqlSetup,
    /// Operator group membership.
    Usermod,
    /// Firewall ports.
    FirewallCmd,
    /// The admin CLI itself (offline CA commands as root).
    Admin,
    /// Service accounts (Remove everything).
    Userdel,
    /// Service groups (Remove everything).
    Groupdel,
    /// Disk use (Health).
    Df,
    /// Listening ports and their holders (Setup's port check).
    Ss,
    /// A unit's last log line (Setup's readiness failure).
    Journalctl,
}

impl Program {
    /// The absolute path run.
    #[must_use]
    pub fn path(self) -> &'static str {
        match self {
            Program::Systemctl => "/usr/bin/systemctl",
            Program::Sudo => "/usr/bin/sudo",
            Program::Logger => "/usr/bin/logger",
            Program::Curl => "/usr/bin/curl",
            Program::Dnf => "/usr/bin/dnf",
            Program::Rpm => "/usr/bin/rpm",
            Program::Runuser => "/usr/sbin/runuser",
            Program::PostgresqlSetup => "/usr/bin/postgresql-setup",
            Program::Usermod => "/usr/sbin/usermod",
            Program::FirewallCmd => "/usr/bin/firewall-cmd",
            Program::Admin => "/usr/bin/openvibes-admin",
            Program::Userdel => "/usr/sbin/userdel",
            Program::Groupdel => "/usr/sbin/groupdel",
            Program::Df => "/usr/bin/df",
            Program::Ss => "/usr/sbin/ss",
            Program::Journalctl => "/usr/bin/journalctl",
        }
    }
}

/// What a command produced.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Output {
    /// Exit status; -1 when killed by a signal.
    pub status: i32,
    /// Standard output, lossily decoded.
    pub stdout: String,
    /// Standard error, lossily decoded.
    pub stderr: String,
}

/// Runs commands; the real one is [`SystemRunner`], tests use a fake.
pub trait Runner {
    /// Runs `program` with `args`, stdin closed, and waits for it.
    fn run(&self, program: Program, args: &[&str]) -> std::io::Result<Output>;
    /// Runs `program` with `args` and `input` on stdin, and waits for it.
    fn run_with_input(
        &self,
        program: Program,
        args: &[&str],
        input: &[u8],
    ) -> std::io::Result<Output>;
}

fn output(output: std::process::Output) -> Output {
    Output {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Runs commands on this host.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

impl Runner for SystemRunner {
    // The one place the host backend starts processes (admin TUI spec §4):
    // one of the `Program`s, never a shell. clippy.toml forbids Command
    // everywhere else.
    #[allow(clippy::disallowed_types)]
    fn run(&self, program: Program, args: &[&str]) -> std::io::Result<Output> {
        let result = std::process::Command::new(program.path())
            .args(args)
            // C locale: sudo's, dnf's and systemctl's messages are parsed.
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .output()?;
        Ok(output(result))
    }

    // As `run`, with stdin piped: the second of the two process starts here.
    #[allow(clippy::disallowed_types)]
    fn run_with_input(
        &self,
        program: Program,
        args: &[&str],
        input: &[u8],
    ) -> std::io::Result<Output> {
        use std::io::Write;
        let mut child = std::process::Command::new(program.path())
            .args(args)
            // C locale: sudo's, dnf's and systemctl's messages are parsed.
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        // ponytail: stdin is written before output is read; fine because the
        // helper reads all of stdin (at most 64 KiB) before writing anything.
        let written = child
            .stdin
            .take()
            .map_or(Ok(()), |mut stdin| stdin.write_all(input));
        let result = child.wait_with_output()?;
        // A child that refused before reading (sudo) closes the pipe; its own
        // error text is the useful one.
        if result.status.success() {
            written?;
        }
        Ok(output(result))
    }
}
