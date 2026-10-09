//! Database commands run as the `openvibes-admin` service account: only it
//! reads `admin.toml` and has the database's peer login (board #79). Run
//! as the operator or as root, the CLI starts itself again as that account
//! instead of failing with a bare configuration error.

#[allow(clippy::disallowed_types)]
use std::process::Command;
use std::{
    ffi::OsString,
    os::unix::process::CommandExt,
    process::{ExitCode, Stdio},
};

use platform_config::ConfigError;

const ADMIN: &str = "/usr/bin/openvibes-admin";
pub const DEFAULT_CONFIG: &str = "/etc/openvibes/admin.toml";

/// How to run a database command.
#[derive(Debug, Eq, PartialEq)]
pub enum RunAs {
    /// As this process: it can read the configuration (or was pointed at
    /// another one on purpose).
    Here,
    /// Root: `runuser -u openvibes-admin`.
    Runuser,
    /// An operator: `sudo -n -u openvibes-admin` (the operators' sudoers
    /// rule, no password).
    Sudo,
}

/// The choice for `uid` with the packaged configuration path or not, and
/// what loading it gave.
pub fn choose(uid: u32, default_config: bool, loaded: Result<(), &ConfigError>) -> RunAs {
    match (default_config, uid, loaded) {
        (false, _, _) => RunAs::Here,
        // Root reads the file but has no database login.
        (true, 0, _) => RunAs::Runuser,
        (true, _, Err(ConfigError::PermissionDenied)) => RunAs::Sudo,
        _ => RunAs::Here,
    }
}

/// Starts this command again as the service account; returns only if that
/// cannot happen, with the reason printed.
// One of the places the platform starts a process (clippy.toml): sudo or
// runuser with fixed options and this same binary, never a shell; the
// arguments are the caller's own, as typed.
#[allow(clippy::disallowed_types)]
pub fn rerun(how: &RunAs) -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut command = match how {
        RunAs::Here => return ExitCode::FAILURE,
        RunAs::Runuser => {
            let mut command = Command::new("/usr/sbin/runuser");
            command.args(["-u", "openvibes-admin", "--", ADMIN]);
            command
        }
        RunAs::Sudo => {
            // Only when the operators' rule lets this user in without a
            // password; otherwise say what to do instead of prompting.
            let allowed = Command::new("/usr/bin/sudo")
                .args(["-n", "-l", "-u", "openvibes-admin", ADMIN])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
            if !allowed {
                eprintln!(
                    "openvibes-admin: {DEFAULT_CONFIG}: permission denied. Members of \
                     openvibes-operators have access (just added? log out and in again); \
                     otherwise open Setup with `sudo openvibes-admin`."
                );
                return ExitCode::FAILURE;
            }
            let mut command = Command::new("/usr/bin/sudo");
            command.args(["-n", "-u", "openvibes-admin", ADMIN]);
            command
        }
    };
    let error = command.args(args).exec();
    eprintln!("openvibes-admin: could not run as openvibes-admin: {error}");
    ExitCode::FAILURE
}

/// This process's user id.
pub fn uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").ok().map(|m| m.uid())
}

#[cfg(test)]
mod tests {
    use platform_config::ConfigError;

    use super::{RunAs, choose};

    #[test]
    fn only_the_packaged_configuration_switches_account() {
        // The user's case (#1059): an operator, admin.toml 0640.
        let denied = Err(&ConfigError::PermissionDenied);
        assert_eq!(choose(1000, true, denied), RunAs::Sudo);
        assert_eq!(
            choose(0, true, Ok(())),
            RunAs::Runuser,
            "root has no database login"
        );
        assert_eq!(choose(967, true, Ok(())), RunAs::Here, "the account itself");
        assert_eq!(choose(1000, true, Err(&ConfigError::Invalid)), RunAs::Here);
        // A config given on the command line (tests, a second platform).
        assert_eq!(choose(1000, false, denied), RunAs::Here);
        assert_eq!(choose(0, false, Ok(())), RunAs::Here);
    }
}
