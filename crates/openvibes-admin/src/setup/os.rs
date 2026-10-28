//! Operating system updates (TUI rework §6): the root helper's `os-check`,
//! `os-update` and `os-restart`. Plain `dnf`; the counts go to
//! [`OS_UPDATES_FILE`] so the TUI reads the last check without a password.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use platform_host::{
    os_updates::{OS_UPDATES_FILE, OsUpdates},
    runner::{
        Program::{Dnf, Systemctl},
        Runner,
    },
};

/// `dnf check-update` exits 100 when packages are waiting.
const UPDATES_WAITING: i32 = 100;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| i64::try_from(since.as_secs()).unwrap_or(0))
}

fn tail(text: &str) -> String {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    lines[lines.len().saturating_sub(3)..].join(" / ")
}

/// Asks dnf what is waiting, keeps the answer and returns it.
pub(crate) fn check<R: Runner>(runner: &R, root: &Path, at: i64) -> Result<OsUpdates, String> {
    let waiting = runner
        .run(Dnf, &["-q", "--refresh", "check-update"])
        .map_err(|error| format!("dnf: {error}"))?;
    let listing = match waiting.status {
        0 | UPDATES_WAITING => waiting.stdout,
        _ => return Err(format!("dnf could not check: {}", tail(&waiting.stderr))),
    };
    // Without advisory data the security count is simply zero.
    let security = runner
        .run(Dnf, &["-q", "updateinfo", "list", "--security"])
        .ok()
        .filter(|out| out.status == 0)
        .map(|out| out.stdout)
        .unwrap_or_default();
    // Exit 1 and no error text: a restart is needed.
    let restart = runner
        .run(Dnf, &["-q", "needs-restarting", "-r"])
        .is_ok_and(|out| out.status == 1 && !out.stderr.contains("Error"));
    let found = OsUpdates::from_listings(&listing, &security, restart, at);
    save(root, &found)?;
    Ok(found)
}

fn save(root: &Path, found: &OsUpdates) -> Result<(), String> {
    let path = root.join(OS_UPDATES_FILE.trim_start_matches('/'));
    let err = |error: std::io::Error| format!("{}: {error}", path.display());
    let temp = path.with_extension("new");
    fs::write(&temp, found.to_file()).map_err(err)?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o644)).map_err(err)?;
    fs::rename(&temp, &path).map_err(err)
}

fn line(found: &OsUpdates) -> String {
    format!(
        "done\t{}\t{}\t{}",
        found.total, found.security, found.restart
    )
}

/// `os-check`: prints `done<TAB>TOTAL<TAB>SECURITY<TAB>RESTART`.
pub(crate) fn run_check<R: Runner>(runner: &R, root: &Path) -> Result<String, String> {
    check(runner, root, now()).map(|found| line(&found))
}

/// `os-update`: everything dnf has, then a new check; prints as `os-check`.
pub(crate) fn run_update<R: Runner>(runner: &R, root: &Path) -> Result<String, String> {
    let upgraded = runner
        .run(Dnf, &["-y", "--refresh", "upgrade"])
        .map_err(|error| format!("dnf: {error}"))?;
    if upgraded.status != 0 {
        return Err(format!("dnf upgrade failed: {}", tail(&upgraded.stderr)));
    }
    run_check(runner, root)
}

/// `os-restart`: asks systemd to reboot; prints `done<TAB>restarting`.
pub(crate) fn run_restart<R: Runner>(runner: &R) -> Result<String, String> {
    let out = runner
        .run(Systemctl, &["reboot"])
        .map_err(|error| format!("systemctl: {error}"))?;
    if out.status != 0 {
        return Err(format!("could not restart: {}", tail(&out.stderr)));
    }
    Ok("done\trestarting".into())
}

#[cfg(test)]
#[path = "os_tests.rs"]
mod tests;
