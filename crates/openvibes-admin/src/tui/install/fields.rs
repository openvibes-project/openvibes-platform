//! The checks on the typed fields and the port proposal, shared by Quick
//! install and the five steps.

use std::path::Path;

use platform_host::Host;

use super::Install;
use crate::setup::{
    plan::{MAX_SANS, check_name, check_san},
    ports,
};

/// The root key file: absolute, new, in a folder that exists. `exists`
/// answers for files and folders alike (tests pass a list).
pub fn check_root_key(path: &str, exists: impl Fn(&str) -> bool) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err("The path must start with /.".into());
    }
    if exists(path) {
        return Err("That file already exists: choose another name.".into());
    }
    let folder = Path::new(path)
        .parent()
        .map_or("/".into(), |p| p.display().to_string());
    if !exists(&folder) {
        return Err(format!("The folder {folder} does not exist."));
    }
    Ok(())
}

/// The host name and the other names (comma separated), as the plan will
/// take them.
pub fn check_names(hostname: &str, sans: &str) -> Result<(), String> {
    let hostname = hostname.trim();
    if hostname.is_empty() {
        return Err("The host name is needed.".into());
    }
    if check_name(hostname).is_err() {
        return Err("Not a DNS name: letters, digits, dots and dashes.".into());
    }
    let others: Vec<&str> = sans
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if others.len() > MAX_SANS {
        return Err(format!("At most {MAX_SANS} other names."));
    }
    for (i, san) in others.iter().enumerate() {
        if check_san(san).is_err() {
            return Err(format!(
                "{san} is not a DNS name or an address: letters, digits, dots and dashes."
            ));
        }
        if *san == hostname || others[..i].contains(san) {
            return Err(format!("{san} is already in the list."));
        }
    }
    Ok(())
}

impl Install {
    /// The first typed field the plan would refuse: its row on Quick
    /// install (0 host name, 1 other names, 2 root key) and why.
    pub fn problem(&self, exists: impl Fn(&str) -> bool) -> Option<(usize, String)> {
        if let Err(why) = check_names(&self.hostname, "") {
            return Some((0, why));
        }
        if let Err(why) = check_names(&self.hostname, &self.sans) {
            return Some((1, why));
        }
        check_root_key(self.root_key_out.trim(), exists)
            .err()
            .map(|why| (2, why))
    }
}

/// A default port another program holds, and the free one chosen for it.
pub(in crate::tui) struct Moved {
    /// 0 console, 1 ingest, 2 distribution.
    pub index: usize,
    pub default: u16,
    pub port: u16,
    /// Who holds the default, when the listing says.
    pub holder: String,
}

/// The three ports and the ones moved: each default another process holds
/// gets the first free port (from 8443 for the console, 18425 for ingest
/// and distribution). Unprivileged, so the holder is rarely known here;
/// Setup's own check (as root) names it if it is still there.
/// The proposal starts from the ports in `start`; a port the platform's own
/// service holds (`ours`) stays.
fn propose_from<H: Host>(
    host: &H,
    start: [u16; 3],
    ours: impl Fn(usize) -> bool,
) -> ([u16; 3], Vec<Moved>) {
    let holder = |port: u16| {
        host.listeners(port)
            .map(|lines| ports::parse(&lines).map(|(who, _)| who))
            .map_err(|error| error.to_string())
    };
    let mut chosen = start;
    let mut moved = Vec::new();
    for (index, from) in [8443, 18425, 18425].into_iter().enumerate() {
        let default = start[index];
        if ours(index) {
            continue;
        }
        // Free, or unknown: Setup checks again before starting.
        let Ok(Some(who)) = holder(default) else {
            continue;
        };
        let free = |port: u16| Ok(chosen.contains(&port) || holder(port)?.is_some());
        let Ok(port) = ports::suggest(from, free) else {
            continue;
        };
        chosen[index] = port;
        moved.push(Moved {
            index,
            default,
            port,
            holder: who,
        });
    }
    (chosen, moved)
}

/// Install's ports, moved off the ones another program holds (not the
/// platform's own running service: `ours`); each moved row says why, and
/// the note for Quick install's Install row says which.
pub fn propose_ports<H: Host>(
    host: &H,
    install: &mut Install,
    ours: impl Fn(usize) -> bool,
) -> Option<String> {
    let start = [
        &install.console_port,
        &install.ingest_port,
        &install.distribution_port,
    ]
    .map(|p| p.trim().parse::<u16>().unwrap_or(0));
    let (chosen, moved) = propose_from(host, start, ours);
    install.console_port = chosen[0].to_string();
    install.ingest_port = chosen[1].to_string();
    install.distribution_port = chosen[2].to_string();
    for m in &moved {
        install.proposed[m.index] = Some(format!("{} is in use by {}", m.default, m.holder));
    }
    let notes: Vec<String> = moved
        .iter()
        .map(|m| {
            let what = ["the console", "ingest", "distribution"][m.index];
            format!(
                "{} is in use by {}: {what} uses {}",
                m.default, m.holder, m.port
            )
        })
        .collect();
    (!notes.is_empty()).then(|| notes.join("; "))
}

/// The free default root key file in `home`, or empty without a home.
pub(super) fn default_root_key(home: Option<&str>) -> String {
    home.map(|home| free_root_key(home, |path| Path::new(path).exists()))
        .unwrap_or_default()
}

/// `HOME/openvibes-root-ca.key`, or `-2`, `-3`… when taken: Remove
/// everything keeps the old root key (it is the user's), so a new install
/// must not stop on it (#87).
fn free_root_key(home: &str, exists: impl Fn(&str) -> bool) -> String {
    crate::tui::maint::backup::free_path(&format!("{home}/openvibes-root-ca"), "key", exists)
}

#[cfg(test)]
mod root_key_tests {
    #[test]
    fn the_default_root_key_name_skips_taken_files() {
        let taken = ["/h/openvibes-root-ca.key", "/h/openvibes-root-ca-2.key"];
        assert_eq!(
            super::free_root_key("/h", |p| taken.contains(&p)),
            "/h/openvibes-root-ca-3.key"
        );
        assert_eq!(
            super::free_root_key("/h", |_| false),
            "/h/openvibes-root-ca.key"
        );
    }
}
