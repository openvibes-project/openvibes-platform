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
    os_updates::{OS_UPDATES_FILE, OsUpdates, UPDATE_UNIT, check_update_packages, restart_answer},
    runner::{
        Program::{Dnf, Systemctl, SystemdRun},
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

/// The `check-update` listing; exit 100 is "updates waiting", not an error.
fn listing<R: Runner>(runner: &R, args: &[&str]) -> Result<String, String> {
    let out = runner
        .run(Dnf, args)
        .map_err(|error| format!("dnf: {error}"))?;
    match out.status {
        0 | UPDATES_WAITING => Ok(out.stdout),
        _ => Err(format!("dnf could not check: {}", tail(&out.stderr))),
    }
}

/// Asks dnf what is waiting, keeps the answer and returns it. `restart_if_unknown`
/// is the answer when `needs-restarting` gives none (plugin missing).
pub(crate) fn check<R: Runner>(
    runner: &R,
    root: &Path,
    at: i64,
    restart_if_unknown: bool,
) -> Result<OsUpdates, String> {
    let all = listing(runner, &["-q", "--refresh", "check-update"])?;
    // Without advisory data the security count is simply zero.
    let security = listing(runner, &["-q", "check-update", "--security"]).unwrap_or_default();
    let restart = runner
        .run(Dnf, &["-q", "needs-restarting", "-r"])
        .ok()
        .and_then(|out| restart_answer(&out.stdout))
        .unwrap_or(restart_if_unknown);
    let found = OsUpdates::from_listings(&all, &security, restart, at);
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

fn line(found: &OsUpdates, upgraded: usize) -> String {
    format!(
        "done\t{}\t{}\t{}\t{upgraded}",
        found.total, found.security, found.restart
    )
}

/// `os-check`: prints `done<TAB>TOTAL<TAB>SECURITY<TAB>RESTART<TAB>0`.
pub(crate) fn run_check<R: Runner>(runner: &R, root: &Path) -> Result<String, String> {
    check(runner, root, now(), false).map(|found| line(&found, 0))
}

/// `os-update`: everything dnf has, in a transient unit so a dropped
/// terminal cannot stop it half way, then a new check; prints as `os-check`
/// with the number of packages that were upgraded.
pub(crate) fn run_update<R: Runner>(runner: &R, root: &Path) -> Result<String, String> {
    let before = listing(runner, &["-q", "--refresh", "check-update"])?;
    let waiting = check_update_packages(&before);
    let kernel = waiting
        .iter()
        .any(|name| name == "kernel" || name.starts_with("kernel-core"));
    let unit = format!("--unit={UPDATE_UNIT}");
    let upgraded = runner
        .run(
            SystemdRun,
            &[
                &unit,
                "--collect",
                "--wait",
                "--pipe",
                "--quiet",
                "/usr/bin/dnf",
                "-y",
                "--refresh",
                "upgrade",
            ],
        )
        .map_err(|error| format!("systemd-run: {error}"))?;
    let failure = (upgraded.status != 0).then(|| {
        if upgraded.stderr.contains("already") {
            "An update is already running".to_owned()
        } else {
            format!("dnf upgrade failed: {}", tail(&upgraded.stderr))
        }
    });
    // Best effort after a failure: the state should still tell the truth.
    let found = check(runner, root, now(), kernel);
    if let Some(error) = failure {
        return Err(error);
    }
    let found = found?;
    let after = listing(runner, &["-q", "check-update"]).unwrap_or_default();
    let left = check_update_packages(&after);
    let done = waiting.iter().filter(|name| !left.contains(name)).count();
    Ok(line(&found, done))
}

/// `os-restart`: asks systemd to reboot, unless an update or a Setup run
/// is half done; prints `done<TAB>restarting`.
pub(crate) fn run_restart<R: Runner>(runner: &R, root: &Path) -> Result<String, String> {
    let updating = runner
        .run(Systemctl, &["is-active", "--quiet", UPDATE_UNIT])
        .is_ok_and(|out| out.status == 0);
    if updating {
        return Err("An update is running; restart when it is done".into());
    }
    let _setup = crate::setup::system::lock(root)?;
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
