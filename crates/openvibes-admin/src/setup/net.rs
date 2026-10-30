//! The appliance's network verbs (TUI rework §7): `net-apply`, `net-keep`,
//! `net-revert` and `hostname-set`. The wired connection's IPv4 settings go
//! through `nmcli`; since a wrong address can cut the very session that set
//! it, `net-apply` first writes the old settings to
//! [`PENDING_FILE`] and starts a transient timer that puts them back after
//! [`KEEP_SECONDS`] seconds unless `net-keep` stops it. Every value is
//! checked by `platform_host::network` before it reaches a command line.

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

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

fn pending_path(root: &Path) -> std::path::PathBuf {
    root.join(PENDING_FILE)
}

/// The wired connection, its settings as they are now.
fn current<R: Runner>(runner: &R) -> Result<NetInfo, String> {
    let active = nmcli(
        runner,
        &[
            "-t",
            "-f",
            "NAME,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ],
    )?;
    let (connection, device) = network::wired_connection(&active)
        .ok_or("no wired connection is active under NetworkManager")?;
    let mut info = NetInfo {
        connection,
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
            &info.connection,
        ],
    )?;
    network::read_config(&mut info, &config);
    Ok(info)
}

fn modify<R: Runner>(runner: &R, connection: &str, values: [&str; 6]) -> Result<(), String> {
    let [method, addresses, gateway, dns, search, ignore_auto_dns] = values;
    nmcli(
        runner,
        &[
            "connection",
            "modify",
            connection,
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
    nmcli(runner, &["connection", "up", connection]).map(|_| ())
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
        connection: info.connection.clone(),
        method: match info.method {
            Some(network::Method::Fixed) => "manual",
            Some(network::Method::Dhcp) => "auto",
            None => {
                return Err("this connection's IPv4 method is not one this screen manages".into());
            }
        }
        .into(),
        addresses: info.address.clone(),
        gateway: info.gateway.clone(),
        dns: info.dns.join(","),
        search: info.search.clone(),
        ignore_auto_dns: if info.dns_auto { "no" } else { "yes" }.into(),
    };
    write_pending(root, &snapshot)?;
    let applied = modify(
        runner,
        &info.connection,
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
        // Nothing was promised yet: put the old settings back at once.
        let _ = run_revert(runner, root);
        return Err(error);
    }
    let seconds = KEEP_SECONDS.to_string();
    let timer = runner
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
        .map_err(|error| format!("systemd-run: {error}"));
    match timer {
        Ok(out) if out.status == 0 => Ok(format!("done\tpending\t{KEEP_SECONDS}")),
        other => {
            // Without the timer there is no way back: do not leave it changed.
            let _ = run_revert(runner, root);
            Err(match other {
                Ok(out) => format!("could not start the rollback timer: {}", tail(&out.stderr)),
                Err(error) => error,
            })
        }
    }
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
/// `done<TAB>kept` or `done<TAB>nothing pending`.
pub(crate) fn run_keep<R: Runner>(runner: &R, root: &Path) -> Result<String, String> {
    let pending = pending_path(root);
    if !pending.exists() {
        return Ok("done\tnothing pending".into());
    }
    let timer = format!("{REVERT_UNIT}.timer");
    let out = runner
        .run(Systemctl, &["stop", &timer])
        .map_err(|error| format!("systemctl: {error}"))?;
    if out.status != 0 {
        return Err(format!(
            "could not stop the rollback timer, so the old settings come back: {}",
            tail(&out.stderr)
        ));
    }
    fs::remove_file(&pending).map_err(|error| format!("{}: {error}", pending.display()))?;
    Ok("done\tkept".into())
}

/// `net-revert` (also run by the timer): puts the old settings back; prints
/// `done<TAB>reverted` or `done<TAB>nothing pending`. The old settings stay
/// on file if they cannot be restored, so it can be tried again.
pub(crate) fn run_revert<R: Runner>(runner: &R, root: &Path) -> Result<String, String> {
    let pending = pending_path(root);
    let Ok(text) = fs::read_to_string(&pending) else {
        return Ok("done\tnothing pending".into());
    };
    let old = Snapshot::decode(&text).ok_or("the saved settings are unreadable")?;
    modify(
        runner,
        &old.connection,
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
    let _ = runner.run(Systemctl, &["stop", &format!("{REVERT_UNIT}.timer")]);
    Ok("done\treverted".into())
}

/// `hostname-set NAME`: prints `done<TAB>NAME`.
pub(crate) fn run_hostname<R: Runner>(runner: &R, name: &str) -> Result<String, String> {
    if !network::host_name(name) {
        return Err(format!("{name} is not a host name"));
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
