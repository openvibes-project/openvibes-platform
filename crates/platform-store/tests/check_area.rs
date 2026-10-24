//! The area of a compliance check (step 5c ruling 3): the store's map and
//! its SQL twin `console_check_area` (schema 63) agree.

mod common;

use platform_store::check_area::{check_area, check_collectors};

/// Every baseline and hardening-linux-l1 rule ID (openvibes-rules 65ff4c0,
/// `baseline/rules.json` and `hardening/linux-l1/rules.json`) and a few
/// others: the store's map and its SQL twin agree.
#[tokio::test]
async fn check_area_parity() {
    assert_eq!(RULE_IDS.split_whitespace().count(), 85);
    let (db, c) = common::migrated().await;
    let ids: Vec<&str> = RULE_IDS
        .split_whitespace()
        .chain(["site.custom", "harden.unknown.x", "", "port", "test.x"])
        .collect();
    let sql: Vec<String> = c
        .query("SELECT console_check_area(unnest($1::text[]))", &[&ids])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let rust: Vec<&str> = ids.iter().map(|id| check_area(id)).collect();
    assert_eq!(sql, rust);
    assert!(rust.iter().take(85).all(|a| *a != "Other"), "{rust:?}");
    db.drop().await;
}

const RULE_IDS: &str = "package.nis_server.installed package.rsh_server.installed
package.talk_server.installed package.telnet_server.installed package.tftp_server.installed
package.xinetd.installed port.cassandra.exposed port.consul.exposed port.couchdb.exposed
port.docker_api.exposed port.elasticsearch.exposed port.etcd.exposed port.ftp.exposed
port.influxdb.exposed port.kafka.exposed port.kibana.exposed port.kubelet.exposed
port.ldap.exposed port.memcached.exposed port.mongodb.exposed port.mssql.exposed
port.mysql.exposed port.nfs.exposed port.node_exporter.exposed port.ollama.exposed
port.oracle.exposed port.postgresql.exposed port.rabbitmq_management.exposed port.rdp.exposed
port.redis.exposed port.rpcbind.exposed port.rsh.exposed port.smb.exposed port.snmp.exposed
port.ssh.exposed port.telnet.exposed port.tftp.exposed port.vnc.exposed port.winrm.exposed
port.x11.exposed port.zookeeper.exposed test.openvibes.running
harden.accounts.empty_password harden.accounts.extra_uid0 harden.accounts.system_shell
harden.files.crontab harden.files.grub_cfg harden.files.gshadow harden.files.passwd
harden.files.shadow harden.fs.protected_links harden.fs.suid_dumpable harden.kernel.aslr
harden.kernel.dmesg_restrict harden.kernel.kptr_restrict harden.kernel.ptrace_scope
harden.kernel.unprivileged_bpf harden.login.faillock harden.login.hash_method
harden.login.pwquality_minlen harden.lsm.apparmor_off harden.lsm.selinux_off
harden.lsm.selinux_permissive harden.modules.rare_protocols harden.net.accept_redirects
harden.net.accept_redirects_v6 harden.net.accept_source_route harden.net.accept_source_route_v6
harden.net.icmp_broadcasts harden.net.ip_forward harden.net.rp_filter harden.net.send_redirects
harden.net.syncookies harden.services.avahi harden.ssh.config_permissions
harden.ssh.hostbased_authentication harden.ssh.ignore_rhosts harden.ssh.log_level
harden.ssh.login_grace_time harden.ssh.max_auth_tries harden.ssh.password_authentication
harden.ssh.permit_empty_passwords harden.ssh.permit_root_login harden.ssh.permit_user_environment
harden.ssh.x11_forwarding";

#[test]
fn collectors_by_prefix() {
    assert_eq!(check_collectors("port.ssh.exposed"), Some(&["ports"][..]));
    assert_eq!(
        check_collectors("package.xinetd.installed"),
        Some(&["packages"][..])
    );
    assert_eq!(
        check_collectors("harden.services.avahi"),
        Some(&["hardening"][..])
    );
    assert_eq!(
        check_collectors("harden.net.ip_forward"),
        Some(&["hardening", "packages"][..])
    );
    assert_eq!(
        check_collectors("test.openvibes.running"),
        Some(&["processes"][..])
    );
    assert_eq!(check_collectors("site.custom"), None);
}
