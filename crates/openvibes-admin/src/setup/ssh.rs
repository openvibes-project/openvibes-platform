//! The appliance's SSH verb (TUI rework §7): `ssh-set` chooses whether keys,
//! passwords or both may sign in. The choice is an `Include` drop-in of
//! `sshd_config`; it is checked with `sshd -t` before `sshd` reloads, and
//! the previous drop-in comes back if the check fails, so a bad file never
//! stands. Keys and passwords cannot both be off.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use platform_host::{
    runner::{
        Program::{Sshd, Systemctl},
        Runner,
    },
    ssh,
};

use super::net::tail;

/// What `ssh-set` takes, all text until it is checked.
#[derive(clap::Args, Clone, Debug)]
pub struct SetArgs {
    /// `yes` or `no`: public keys may sign in.
    #[arg(long)]
    pub keys: String,
    /// `yes` or `no`: passwords may sign in.
    #[arg(long)]
    pub passwords: String,
}

fn put_back(path: &Path, previous: Option<&str>) -> io::Result<()> {
    match previous {
        Some(text) => fs::write(path, text),
        None => match fs::remove_file(path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        },
    }
}

/// `ssh-set --keys yes|no --passwords yes|no`: prints `done<TAB>set`.
pub(crate) fn run_set<R: Runner>(
    runner: &R,
    root: &Path,
    args: &SetArgs,
) -> Result<String, String> {
    let keys = ssh::parse_word(&args.keys)?;
    let passwords = ssh::parse_word(&args.passwords)?;
    ssh::check(keys, passwords)?;
    let path: PathBuf = root.join(ssh::DROP_IN);
    let previous = fs::read_to_string(&path).ok();
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    }
    fs::write(&path, ssh::drop_in(keys, passwords))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let checked = runner
        .run(Sshd, &["-t"])
        .map_err(|error| format!("{}: {error}", Sshd.path()))?;
    if checked.status != 0 {
        put_back(&path, previous.as_deref())
            .map_err(|error| format!("{}: {error}", path.display()))?;
        return Err(format!(
            "sshd would not accept it, so nothing changed: {}",
            tail(&checked.stderr)
        ));
    }
    let reloaded = runner
        .run(Systemctl, &["reload", "sshd.service"])
        .map_err(|error| format!("{}: {error}", Systemctl.path()))?;
    if reloaded.status != 0 {
        return Err(format!("sshd did not reload: {}", tail(&reloaded.stderr)));
    }
    Ok("done\tset".into())
}

#[cfg(test)]
#[path = "ssh_tests.rs"]
mod tests;
