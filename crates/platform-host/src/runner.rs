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
}

/// Runs commands on this host.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

impl Runner for SystemRunner {
    // The one place the host backend starts processes (admin TUI spec §4):
    // one of the four `Program`s, never a shell. clippy.toml forbids Command
    // everywhere else.
    #[allow(clippy::disallowed_types)]
    fn run(&self, program: Program, args: &[&str]) -> std::io::Result<Output> {
        let output = std::process::Command::new(program.path())
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()?;
        Ok(Output {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}
