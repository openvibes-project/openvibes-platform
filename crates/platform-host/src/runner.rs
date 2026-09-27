//! Every command the host backend runs goes through a [`Runner`]: a fixed
//! program path and argument vector, never a shell string.

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
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output>;
}

/// Runs commands on this host.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

impl Runner for SystemRunner {
    // The one place the host backend starts processes (admin TUI spec §4):
    // fixed absolute program paths and argument vectors from `Native`, never a
    // shell. clippy.toml forbids Command everywhere else.
    #[allow(clippy::disallowed_types)]
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        let output = std::process::Command::new(program)
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
