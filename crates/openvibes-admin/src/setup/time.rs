//! The appliance's time verb (TUI rework §7): `time-set` chooses the NTP
//! servers `chrony` asks and the time zone. Chosen servers go in a
//! `confdir` drop-in; since a drop-in can only add sources, the `pool` and
//! `server` lines of the distribution's own `chrony.conf` are commented out
//! (marked, so clearing the list puts them back). Every value is checked by
//! `platform_host::timesync` before it reaches a file or a command line.

use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use platform_host::{
    runner::{
        Program::{Systemctl, Timedatectl},
        Runner,
    },
    timesync,
};

use super::net::tail;

/// What `time-set` takes, all text until it is checked.
#[derive(clap::Args, Clone, Debug)]
pub struct SetArgs {
    /// Comma separated NTP servers; none means the distribution's own.
    #[arg(long, default_value = "")]
    pub servers: String,
    /// The time zone, e.g. `Europe/Stockholm`.
    #[arg(long)]
    pub zone: String,
}

/// Marks a distribution line this verb commented out.
const MARK: &str = "#openvibes# ";
const CONF: &str = "etc/chrony.conf";
const CONFDIR: &str = "confdir /etc/chrony.d";

fn run<R: Runner>(
    runner: &R,
    program: platform_host::runner::Program,
    args: &[&str],
) -> Result<String, String> {
    let out = runner
        .run(program, args)
        .map_err(|error| format!("{}: {error}", program.path()))?;
    if out.status == 0 {
        Ok(out.stdout)
    } else {
        Err(format!("{}: {}", program.path(), tail(&out.stderr)))
    }
}

/// `conf` with its active `pool` and `server` lines commented out.
fn mark_sources(conf: &str) -> String {
    map_lines(conf, |line| {
        let word = line.split_whitespace().next();
        if matches!(word, Some("pool" | "server")) {
            format!("{MARK}{line}")
        } else {
            line.to_owned()
        }
    })
}

/// `conf` with the lines [`mark_sources`] commented out back again.
fn unmark_sources(conf: &str) -> String {
    map_lines(conf, |line| {
        line.strip_prefix(MARK).unwrap_or(line).to_owned()
    })
}

fn map_lines(conf: &str, f: impl Fn(&str) -> String) -> String {
    conf.lines().map(|l| f(l) + "\n").collect()
}

/// `conf` reads the drop-in directory.
fn has_confdir(conf: &str) -> bool {
    conf.lines().any(|line| {
        let mut words = line.split_whitespace();
        matches!(words.next(), Some("confdir" | "include"))
            && words.any(|w| w.starts_with("/etc/chrony.d"))
    })
}

/// Replaces `path` whole (a half-written `chrony.conf` is worse than none).
fn replace(path: &Path, text: &str) -> io::Result<()> {
    let mode = fs::metadata(path).map_or(0o644, |m| m.permissions().mode() & 0o777);
    let temp: PathBuf = path.with_extension("openvibes-new");
    fs::write(&temp, text)?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(mode))?;
    fs::rename(&temp, path)
}

/// `time-set --servers LIST --zone ZONE`: prints `done<TAB>set`.
pub(crate) fn run_set<R: Runner>(
    runner: &R,
    root: &Path,
    args: &SetArgs,
) -> Result<String, String> {
    let servers = timesync::servers(&args.servers)?;
    if !timesync::zone_name(&args.zone) {
        return Err(format!("{} is not a time zone", args.zone));
    }
    let list = run(runner, Timedatectl, &["list-timezones"])?;
    if !timesync::known_zone(&list, &args.zone) {
        return Err(format!("{} is not a time zone this host knows", args.zone));
    }
    let conf_path = root.join(CONF);
    let drop_in = root.join(timesync::DROP_IN);
    let conf = fs::read_to_string(&conf_path)
        .map_err(|error| format!("{}: {error}", conf_path.display()))?;
    let plain = unmark_sources(&conf);
    if servers.is_empty() {
        replace(&conf_path, &plain).map_err(|error| format!("{}: {error}", conf_path.display()))?;
        match fs::remove_file(&drop_in) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", drop_in.display())),
        }
    } else {
        let mut marked = mark_sources(&plain);
        if !has_confdir(&marked) {
            marked.push_str(&format!("\n{CONFDIR}\n"));
        }
        if let Some(dir) = drop_in.parent() {
            fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        }
        fs::write(&drop_in, timesync::drop_in(&servers))
            .map_err(|error| format!("{}: {error}", drop_in.display()))?;
        replace(&conf_path, &marked)
            .map_err(|error| format!("{}: {error}", conf_path.display()))?;
    }
    run(runner, Timedatectl, &["set-timezone", &args.zone])?;
    run(runner, Systemctl, &["restart", "chronyd.service"])?;
    Ok("done\tset".into())
}

#[cfg(test)]
#[path = "time_tests.rs"]
mod tests;
