//! Where a fact comes from on the host (step 5c user decision 3): the file
//! the agent's collectors read for it, shown beside a finding's evidence.
//! Only what the collectors actually read is mapped (openvibes-agent
//! `crates/openvibes-collectors/src/hardening/` and `hardening.rs`; the
//! keys are those of the vendored `protocol/vectors/fact-catalog.json`).
//! Facts not read from a file (ports, packages, processes, running
//! services from cgroups) have none.

/// `file.<name>.*`: catalog name → path (the agent's `files.rs`).
const FILES: [(&str, &str); 25] = [
    ("etc_passwd", "/etc/passwd"),
    ("etc_passwd_backup", "/etc/passwd-"),
    ("etc_shadow", "/etc/shadow"),
    ("etc_shadow_backup", "/etc/shadow-"),
    ("etc_group", "/etc/group"),
    ("etc_group_backup", "/etc/group-"),
    ("etc_gshadow", "/etc/gshadow"),
    ("etc_gshadow_backup", "/etc/gshadow-"),
    ("etc_sshd_config", "/etc/ssh/sshd_config"),
    ("etc_crontab", "/etc/crontab"),
    ("etc_cron_d", "/etc/cron.d"),
    ("etc_cron_hourly", "/etc/cron.hourly"),
    ("etc_cron_daily", "/etc/cron.daily"),
    ("etc_cron_weekly", "/etc/cron.weekly"),
    ("etc_cron_monthly", "/etc/cron.monthly"),
    ("etc_cron_allow", "/etc/cron.allow"),
    ("etc_at_allow", "/etc/at.allow"),
    ("etc_cron_deny", "/etc/cron.deny"),
    ("etc_at_deny", "/etc/at.deny"),
    ("boot_grub2_grub_cfg", "/boot/grub2/grub.cfg"),
    ("boot_grub_grub_cfg", "/boot/grub/grub.cfg"),
    ("etc_issue", "/etc/issue"),
    ("etc_issue_net", "/etc/issue.net"),
    ("etc_motd", "/etc/motd"),
    ("etc_security_opasswd", "/etc/security/opasswd"),
];

/// Fact-key prefix → the file or directory read, first match wins. Some
/// name the first of several sources: `kernel.modules.disabled` also reads
/// `/run/modprobe.d/` and `/usr/lib/modprobe.d/`, `service.enabled`
/// `/usr/lib/systemd/system/`, `pam.pwquality.` `pwquality.conf.d/`, and
/// `os.` falls back to `/usr/lib/os-release`.
const PREFIXES: [(&str, &str); 17] = [
    // Includes are followed from it (the agent's `sshd.rs`).
    ("sshd.", "/etc/ssh/sshd_config"),
    ("accounts.empty_password", "/etc/shadow"),
    ("accounts.", "/etc/passwd"),
    ("login_defs.", "/etc/login.defs"),
    ("pam.pwquality.", "/etc/security/pwquality.conf"),
    ("pam.faillock.", "/etc/security/faillock.conf"),
    ("pam.modules", "/etc/pam.d/"),
    ("auditd.", "/etc/audit/auditd.conf"),
    ("audit.rules.", "/etc/audit/rules.d/"),
    ("mount.", "/proc/1/mountinfo"),
    ("kernel.modules.loaded", "/proc/modules"),
    ("kernel.modules.disabled", "/etc/modprobe.d/"),
    ("kernel.cmdline.", "/proc/cmdline"),
    ("lsm.selinux", "/sys/fs/selinux/enforce"),
    ("lsm.apparmor", "/sys/module/apparmor/parameters/enabled"),
    ("service.enabled", "/etc/systemd/system/"),
    ("os.", "/etc/os-release"),
];

/// The file the agent read `fact_key` from, if any. `sysctl.<name>` is
/// the running value under `/proc/sys` (not `sysctl.d`, which the agent
/// does not read).
#[must_use]
pub(crate) fn fact_file(fact_key: &str) -> Option<String> {
    if let Some(rest) = fact_key.strip_prefix("file.") {
        let (name, _) = rest.split_once('.')?;
        return FILES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, path)| (*path).to_owned());
    }
    if let Some(name) = fact_key.strip_prefix("sysctl.") {
        if name == "kernel.core_pattern_pipe" {
            return Some("/proc/sys/kernel/core_pattern".into());
        }
        let ok = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.');
        return ok.then(|| format!("/proc/sys/{}", name.replace('.', "/")));
    }
    PREFIXES
        .iter()
        .find(|(prefix, _)| fact_key.starts_with(prefix))
        .map(|(_, path)| (*path).to_owned())
}

#[cfg(test)]
mod tests {
    use super::fact_file;

    #[test]
    fn facts_map_to_the_files_the_collectors_read() {
        let f = |k: &str| fact_file(k);
        assert_eq!(
            f("sshd.permitrootlogin").as_deref(),
            Some("/etc/ssh/sshd_config")
        );
        assert_eq!(f("file.etc_shadow.mode").as_deref(), Some("/etc/shadow"));
        assert_eq!(
            f("file.boot_grub2_grub_cfg.owner").as_deref(),
            Some("/boot/grub2/grub.cfg")
        );
        assert_eq!(f("file.unknown.mode"), None);
        assert_eq!(
            f("sysctl.net.ipv4.ip_forward").as_deref(),
            Some("/proc/sys/net/ipv4/ip_forward")
        );
        assert_eq!(
            f("sysctl.kernel.core_pattern_pipe").as_deref(),
            Some("/proc/sys/kernel/core_pattern")
        );
        assert_eq!(f("sysctl.../x"), None);
        assert_eq!(
            f("accounts.empty_password.count").as_deref(),
            Some("/etc/shadow")
        );
        assert_eq!(f("accounts.uid0").as_deref(), Some("/etc/passwd"));
        assert_eq!(f("pam.modules").as_deref(), Some("/etc/pam.d/"));
        assert_eq!(f("port.tcp.exposed"), None);
        assert_eq!(f("package.names"), None);
        assert_eq!(f("service.active"), None, "read from cgroups");
    }

    /// Every hardening fact of the protocol's catalog has a file, but
    /// the ones read from no file.
    #[test]
    fn every_catalog_hardening_fact_is_mapped() {
        let catalog: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../protocol/vectors/fact-catalog.json"
        ))
        .unwrap();
        let unmapped: Vec<&str> = catalog["facts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["key"].as_str())
            .filter(|k| {
                !["port.", "package.", "process.", "service.active"]
                    .iter()
                    .any(|p| k.starts_with(p))
            })
            .filter(|k| fact_file(k).is_none())
            .collect();
        assert!(unmapped.is_empty(), "{unmapped:?}");
    }
}
