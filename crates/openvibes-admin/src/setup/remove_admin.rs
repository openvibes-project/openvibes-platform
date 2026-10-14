//! The last remove step, `admin`: the tool itself, what rpm kept of it, the
//! repository and its signing key. Split from `remove.rs` (size).

use std::{fs, io::ErrorKind, path::Path};

use platform_host::{
    StepState,
    runner::{Program::Rpm, Runner},
};

use super::{Ctx, RemoveArgs, installed};

/// The package repository install.sh writes, and the signing key file it
/// installs next to it (removed once no other OpenVIBES package is left).
const REPO_DIR: &str = "/etc/yum.repos.d";
const KEY_FILE: &str = "/etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes";
/// The OpenVIBES packages key in rpm's database, `gpg-pubkey-<VERSION>-<REL>`:
/// VERSION is the last eight hex digits of the fingerprint with RPM 4 and
/// the whole fingerprint with RPM 6 (see packaging/rpm/openvibes-packages.gpg).
/// Never another key.
const KEY_VERSIONS: [&str; 2] = ["7786da36", "710ad8afb7afe6e864c0cdc4e134baf37786da36"];
/// dnf's per-repository caches (`<repo id>-<16 hex digits>`), and dnf4's
/// top-level files for the repository, by exact name.
const CACHES: [&str; 2] = ["/var/cache/libdnf5", "/var/cache/dnf"];
const DNF4_FILES: [&str; 2] = ["openvibes.solv", "openvibes-filenames.solvx"];
/// Automatic pre-migration dumps (auto_migrate.rs).
pub(super) const BACKUPS: &str = "/var/backups/openvibes";

fn remove_path(path: &Path) -> Result<(), String> {
    let result = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match result {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            Err(format!("{}: {error}", path.display()))
        }
        _ => Ok(()),
    }
}

/// Removes every entry of `dir` that `ours` accepts; their paths. A missing
/// directory is fine; any other error stops the step.
fn remove_matching<R: Runner>(
    ctx: &Ctx<R>,
    dir: &str,
    ours: impl Fn(&str) -> bool,
) -> Result<Vec<String>, String> {
    let entries = match fs::read_dir(ctx.path(dir)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("{dir}: {error}")),
    };
    let mut gone = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("{dir}: {error}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if ours(&name) {
            remove_path(&entry.path())?;
            gone.push(format!("{dir}/{name}"));
        }
    }
    Ok(gone)
}

/// Last: the administration tool itself (this helper is part of it; the
/// running process keeps its file until it exits), what rpm kept of it,
/// its state, and the package repository, its signing key and caches once
/// no other OpenVIBES package is left. Only for the whole platform:
/// removing one part leaves the tool. With `--everything` (a confirmation)
/// nothing may stay; without it the configuration and data are kept and
/// listed.
///
/// Order matters: the package goes after every other fallible operation,
/// because without it no retry is possible; after it only unlinks of fixed
/// paths run. Every part first checks whether it is still there, so a
/// repeat is safe.
pub fn remove_admin<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    if !ctx
        .plan
        .components
        .iter()
        .all(|c| args.components.contains(c))
    {
        return Ok(StepState::Skipped(
            "the administration tool stays: other parts remain".into(),
        ));
    }
    let mut done = Vec::new();
    let others: Vec<String> = ctx
        .ok(Rpm, &["-qa", "openvibes-*"])?
        .lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty() && !l.starts_with("openvibes-admin-"))
        .filter(|l| l != "openvibes-admin")
        .collect();
    let mut notes = Vec::new();
    if others.is_empty() {
        done.extend(remove_matching(ctx, REPO_DIR, |n| {
            n.starts_with("openvibes") && n.ends_with(".repo")
        })?);
        if ctx.exists(KEY_FILE) {
            remove_path(&ctx.path(KEY_FILE))?;
            done.push(KEY_FILE.to_owned());
        }
        for cache in CACHES {
            done.extend(remove_matching(ctx, cache, |n| {
                DNF4_FILES.contains(&n)
                    || n.strip_prefix("openvibes-").is_some_and(|id| {
                        id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            })?);
        }
        // Exit 1 when no key is installed: the output is what counts.
        let keys = ctx.stdout(
            Rpm,
            &[
                "-q",
                "gpg-pubkey",
                "--qf",
                "%{NAME}-%{VERSION}-%{RELEASE}\t%{VERSION}\t%{SUMMARY}\n",
            ],
        )?;
        for line in keys.lines() {
            let mut field = line.split('\t');
            let (Some(name), Some(version), Some(summary)) =
                (field.next(), field.next(), field.next())
            else {
                continue;
            };
            if KEY_VERSIONS.contains(&version) && summary.contains("OpenVIBES packages") {
                ctx.ok(Rpm, &["-e", name])?;
                done.push(name.to_owned());
            }
        }
    } else {
        notes.push(format!(
            "the package repository stays: {} still uses it",
            others.join(" ")
        ));
    }
    if args.confirm.is_some() {
        remove_path(&ctx.path("/var/lib/openvibes-admin"))?;
        remove_path(&ctx.path(BACKUPS))?;
        // Everything in /etc/openvibes except what the retry and rpm need.
        done.extend(remove_matching(ctx, "/etc/openvibes", |n| {
            n != "admin.toml" && n != "setup.toml"
        })?);
        done.push("its data and configuration".into());
    } else {
        notes.push(
            "kept: /etc/openvibes, /var/lib/openvibes-*, /etc/openvibes-agent, \
             the openvibes database and its roles, the service accounts and groups, \
             /var/backups/openvibes"
                .into(),
        );
    }
    // The last fallible call. `rpm -e` refuses when something depends on
    // the tool; dnf would silently remove the dependants.
    if installed(ctx, "openvibes-admin") {
        ctx.ok(Rpm, &["-e", "openvibes-admin"])?;
        done.insert(0, "openvibes-admin".to_owned());
    }
    if args.confirm.is_some() {
        // Only unlinks of fixed paths remain; there is nothing left to retry with.
        let _ = remove_matching(ctx, "/etc/sudoers.d", |n| {
            n.starts_with("openvibes-operators")
        });
        let _ = remove_path(&ctx.path("/etc/openvibes"));
        // systemd's "last ran" stamp of the nightly clean-up timer.
        let _ = remove_matching(ctx, "/var/lib/systemd/timers", |n| {
            n.starts_with("stamp-openvibes-")
        });
    }
    let text = if done.is_empty() {
        "nothing left to remove".to_owned()
    } else {
        format!("removed {}", done.join(", "))
    };
    if others.is_empty() && args.confirm.is_some() {
        notes.push(
            "this program closes here: nothing of OpenVIBES remains to remove by hand".into(),
        );
    } else if others.is_empty() {
        notes.push("this program closes here; the rest is removed".into());
    } else {
        notes.push("this program closes here".into());
    }
    Ok(StepState::Done(format!("{text}; {}", notes.join("; "))))
}

/// The job is over. A finished whole-platform run also drops the lock file
/// it holds (tmpfs, but nothing of ours stays); a skipped one is not the end.
pub fn finish<R: Runner>(ctx: &Ctx<R>, state: &StepState) {
    ctx.job_end();
    if matches!(state, StepState::Done(_)) {
        let _ = fs::remove_file(ctx.path("/run/openvibes-admin/setup.lock"));
        let _ = fs::remove_dir(ctx.path("/run/openvibes-admin"));
    }
}
