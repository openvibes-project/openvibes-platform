//! The appliance's network verbs (TUI rework §7): `net-apply`, `net-keep`,
//! `net-revert` and `hostname-set`. The wired connection's IPv4 settings go
//! through `nmcli`; since a wrong address can cut the very session that set
//! it, `net-apply` first writes the old settings to
//! [`PENDING_FILE`] and starts a transient timer that puts them back after
//! [`KEEP_SECONDS`] seconds unless `net-keep` stops it. The timer is armed
//! before anything changes and every verb holds one lock, so a helper that
//! dies half way, or `net-keep` meeting the firing timer, cannot leave a
//! change nobody will undo. Every value is checked by `platform_host::network`
//! before it reaches a command line.

use std::{
    fs, io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use platform_host::{
    network::{self, KEEP_SECONDS, NetInfo, PENDING_FILE, REVERT_UNIT, Snapshot},
    runner::{
        Program::{Admin, Hostnamectl, Nmcli, Systemctl, SystemdRun},
        Runner,
    },
};

/// The arguments of `net-apply`, all text until they are checked.
#[derive(clap::Args, Clone, Debug)]
pub struct ApplyArgs {
    /// `dhcp` or `fixed`.
    #[arg(long)]
    pub mode: String,
    /// Fixed only: ADDRESS/PREFIX.
    #[arg(long, default_value = "")]
    pub address: String,
    /// Fixed only: the gateway.
    #[arg(long, default_value = "")]
    pub gateway: String,
    /// Comma separated DNS servers; none with DHCP means DHCP's.
    #[arg(long, default_value = "")]
    pub dns: String,
    /// The search domain.
    #[arg(long, default_value = "")]
    pub search: String,
}

fn tail(text: &str) -> String {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    lines[lines.len().saturating_sub(3)..].join(" / ")
}

fn nmcli<R: Runner>(runner: &R, args: &[&str]) -> Result<String, String> {
    let out = runner
        .run(Nmcli, args)
        .map_err(|error| format!("nmcli: {error}"))?;
    if out.status == 0 {
        Ok(out.stdout)
    } else {
        Err(format!("nmcli: {}", tail(&out.stderr)))
    }
}

/// Seconds the timer waits while the change is being made (bringing a
/// connection up can take a minute and a half); it is set to
/// [`KEEP_SECONDS`] once the connection is up.
const SETTLE_SECONDS: u64 = 150;

fn pending_path(root: &Path) -> PathBuf {
    root.join(PENDING_FILE)
}

/// Holds `/run/openvibes-admin/net.lock` while a verb works; a second verb
/// (the firing timer, `net-keep`) waits its turn.
fn lock(root: &Path) -> Result<fs::File, String> {
    let dir = root.join("run/openvibes-admin");
    fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let path = dir.join("net.lock");
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.lock()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(file)
}

fn timer_name() -> String {
    format!("{REVERT_UNIT}.timer")
}

/// The wired connection, its settings as they are now.
fn current<R: Runner>(runner: &R) -> Result<NetInfo, String> {
    let active = nmcli(
        runner,
        &[
            "-t",
            "-f",
            "NAME,UUID,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ],
    )?;
    let (connection, uuid, device) = network::wired_connection(&active)
        .ok_or("no wired connection is active under NetworkManager")?;
    let mut info = NetInfo {
        connection,
        uuid,
        device,
        ..NetInfo::default()
    };
    let config = nmcli(
        runner,
        &[
            "-t",
            "-f",
            "ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv4.dns-search,ipv4.ignore-auto-dns",
            "connection",
            "show",
            "uuid",
            &info.uuid,
        ],
    )?;
    network::read_config(&mut info, &config);
    Ok(info)
}

fn modify<R: Runner>(runner: &R, uuid: &str, values: [&str; 6]) -> Result<(), String> {
    let [method, addresses, gateway, dns, search, ignore_auto_dns] = values;
    nmcli(
        runner,
        &[
            "connection",
            "modify",
            "uuid",
            uuid,
            "ipv4.method",
            method,
            "ipv4.addresses",
            addresses,
            "ipv4.gateway",
            gateway,
            "ipv4.dns",
            dns,
            "ipv4.dns-search",
            search,
            "ipv4.ignore-auto-dns",
            ignore_auto_dns,
        ],
    )?;
    nmcli(runner, &["connection", "up", "uuid", uuid]).map(|_| ())
}

/// (Re)starts the rollback timer to fire in `seconds`.
fn arm<R: Runner>(runner: &R, seconds: u64) -> Result<(), String> {
    // A timer that is still loaded would make the new one fail.
    let _ = runner.run(Systemctl, &["stop", &timer_name()]);
    let seconds = seconds.to_string();
    let out = runner
        .run(
            SystemdRun,
            &[
                "--unit",
                REVERT_UNIT,
                "--on-active",
                &seconds,
                "--collect",
                "--quiet",
                Admin.path(),
                "helper",
                "net-revert",
            ],
        )
        .map_err(|error| format!("systemd-run: {error}"))?;
    if out.status == 0 {
        Ok(())
    } else {
        Err(format!(
            "could not start the rollback timer: {}",
            tail(&out.stderr)
        ))
    }
}

/// `net-apply`: prints `done<TAB>pending<TAB>SECONDS`, or
/// `done<TAB>unchanged` when the settings are already these.
pub(crate) fn run_apply<R: Runner>(
    runner: &R,
    root: &Path,
    args: &ApplyArgs,
) -> Result<String, String> {
    let change = network::change(
        &args.mode,
        &args.address,
        &args.gateway,
        &args.dns,
        &args.search,
    )?;
    let _held = lock(root)?;
    let pending = pending_path(root);
    if pending.exists() {
        return Err("A network change is waiting to be kept or put back; answer it first".into());
    }
    let info = current(runner)?;
    let method = match change.method {
        network::Method::Dhcp => "auto",
        network::Method::Fixed => "manual",
    };
    let own_dns = !change.dns.is_empty();
    let dns = change.dns.join(",");
    let ignore = if own_dns { "yes" } else { "no" };
    let same = info.method == Some(change.method)
        && info.address == change.address
        && info.gateway == change.gateway
        && info.dns == change.dns
        && info.search == change.search
        && info.dns_auto != own_dns;
    if same {
        return Ok("done\tunchanged".into());
    }
    let snapshot = Snapshot {
        uuid: info.uuid.clone(),
        method: match info.method {
            Some(network::Method::Fixed) => "manual",
            Some(network::Method::Dhcp) => "auto",
            None => {
                return Err("this connection's IPv4 method is not one this screen manages".into());
            }
        }
        .into(),
        addresses: info.all_addresses.clone(),
        gateway: info.gateway.clone(),
        dns: info.all_dns.clone(),
        search: info.all_search.clone(),
        ignore_auto_dns: if info.dns_auto { "no" } else { "yes" }.into(),
    };
    write_pending(root, &snapshot)?;
    // The way back first: from here on a helper that dies, or a session
    // that closes, still gets the old settings back.
    if let Err(error) = arm(runner, SETTLE_SECONDS) {
        let _ = fs::remove_file(&pending);
        return Err(error);
    }
    let applied = modify(
        runner,
        &info.uuid,
        [
            method,
            &change.address,
            &change.gateway,
            &dns,
            &change.search,
            ignore,
        ],
    );
    if let Err(error) = applied {
        let _ = revert_locked(runner, root);
        return Err(error);
    }
    // Up: the operator now has KEEP_SECONDS from this moment.
    if let Err(error) = arm(runner, KEEP_SECONDS) {
        let _ = revert_locked(runner, root);
        return Err(error);
    }
    write_pending(root, &snapshot)?;
    Ok(format!("done\tpending\t{KEEP_SECONDS}"))
}

fn write_pending(root: &Path, snapshot: &Snapshot) -> Result<(), String> {
    let path = pending_path(root);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    }
    fs::write(&path, snapshot.encode()).map_err(|error| format!("{}: {error}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// `net-keep`: stops the timer and forgets the old settings; prints
/// `done<TAB>kept` or `done<TAB>nothing pending` (nothing was waiting, or
/// the timer already put the old settings back).
pub(crate) fn run_keep<R: Runner>(runner: &R, root: &Path) -> Result<String, String> {
    let _held = lock(root)?;
    let pending = pending_path(root);
    if !pending.exists() {
        return Ok("done\tnothing pending".into());
    }
    let timer = timer_name();
    let out = runner
        .run(Systemctl, &["stop", &timer])
        .map_err(|error| format!("systemctl: {error}"))?;
    if out.status != 0 {
        // Gone already is fine; one that is running and will not stop is not.
        let running = runner
            .run(Systemctl, &["is-active", "--quiet", &timer])
            .is_ok_and(|out| out.status == 0);
        if running {
            return Err(format!(
                "could not stop the rollback timer, so the old settings come back: {}",
                tail(&out.stderr)
            ));
        }
    }
    fs::remove_file(&pending).map_err(|error| format!("{}: {error}", pending.display()))?;
    Ok("done\tkept".into())
}

/// `net-revert` (also run by the timer): puts the old settings back; prints
/// `done<TAB>reverted` or `done<TAB>nothing pending`. Settings that cannot
/// be restored stay on file so it can be tried again (or `net-keep` clears
/// them); a file that cannot be read is moved aside so it blocks nothing.
pub(crate) fn run_revert<R: Runner>(runner: &R, root: &Path) -> Result<String, String> {
    let _held = lock(root)?;
    revert_locked(runner, root)
}

fn revert_locked<R: Runner>(runner: &R, root: &Path) -> Result<String, String> {
    let pending = pending_path(root);
    let text = match fs::read_to_string(&pending) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok("done\tnothing pending".into());
        }
        Err(error) => return Err(format!("{}: {error}", pending.display())),
    };
    let Some(old) = Snapshot::decode(&text) else {
        let aside = pending.with_extension("bad");
        let _ = fs::rename(&pending, &aside);
        let _ = runner.run(Systemctl, &["stop", &timer_name()]);
        return Err(
            "the saved settings could not be read, so the current ones stay (the file is kept as net-previous.bad)"
                .into(),
        );
    };
    modify(
        runner,
        &old.uuid,
        [
            &old.method,
            &old.addresses,
            &old.gateway,
            &old.dns,
            &old.search,
            &old.ignore_auto_dns,
        ],
    )?;
    fs::remove_file(&pending).map_err(|error| format!("{}: {error}", pending.display()))?;
    // Harmless when the timer is what called us.
    let _ = runner.run(Systemctl, &["stop", &timer_name()]);
    Ok("done\treverted".into())
}

/// `hostname-set NAME`: prints `done<TAB>NAME`.
pub(crate) fn run_hostname<R: Runner>(runner: &R, name: &str) -> Result<String, String> {
    if !network::host_name(name) {
        return Err(format!("{name} is not a host name (at most 64 characters)"));
    }
    let out = runner
        .run(Hostnamectl, &["set-hostname", "--", name])
        .map_err(|error| format!("hostnamectl: {error}"))?;
    if out.status != 0 {
        return Err(format!("hostnamectl: {}", tail(&out.stderr)));
    }
    Ok(format!("done\t{name}"))
}

#[cfg(test)]
#[path = "net_tests.rs"]
mod tests;
