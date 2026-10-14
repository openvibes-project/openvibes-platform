//! Remove steps against the fake runner.
use platform_host::{RemoveStep, StepState};

use super::{RemoveArgs, run};
use crate::setup::{
    fake::{Fake, plan},
    plan::Component::{self, *},
};

pub(super) const GPG: &str = "gpg-pubkey-7786da36-6a0f1e07\t7786da36\tOpenVIBES packages <26064407+itismelime@users.noreply.github.com> public key\n\
                   gpg-pubkey-11111111-1\t11111111\tFedora (44) <fedora-44-primary@fedoraproject.org> public key\n";
/// RPM 6 (Fedora 44): the whole fingerprint is the version.
pub(super) const GPG6: &str = "gpg-pubkey-710ad8afb7afe6e864c0cdc4e134baf37786da36-6a0f1e07\t710ad8afb7afe6e864c0cdc4e134baf37786da36\tOpenVIBES packages <26064407+itismelime@users.noreply.github.com> public key\n\
                    gpg-pubkey-c6e7f081cf80e13146676e88829b606631645531-1\tc6e7f081cf80e13146676e88829b606631645531\tFedora (44) <fedora-44-primary@fedoraproject.org> public key\n";

pub(super) fn admin_answers(fake: &Fake, left: &str) {
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-admin"], 0, "");
    fake.answer(&["/usr/bin/rpm", "-qa", "openvibes-*"], 0, left);
    fake.answer(&["/usr/bin/rpm", "-q", "gpg-pubkey"], 0, GPG);
    fake.answer(&["/usr/bin/rpm", "-e"], 0, "");
}

pub(super) const PG: [&str; 4] = ["/usr/sbin/runuser", "-u", "postgres", "--"];

pub(super) fn args(components: &[Component], confirm: Option<&str>) -> RemoveArgs {
    RemoveArgs {
        components: components.to_vec(),
        backup: None,
        confirm: confirm.map(str::to_owned),
        remember_choice: false,
    }
}

#[test]
fn removing_a_component_stops_it_closes_its_port_and_removes_its_packages() {
    let fake = Fake::new("remove-distribution");
    fake.answer(
        &["/usr/bin/rpm", "-q", "--quiet", "openvibes-distribution"],
        0,
        "",
    );
    fake.answer(&["/usr/bin/systemctl", "disable", "--now"], 0, "");
    fake.answer(&["/usr/bin/firewall-cmd", "--state"], 0, "running\n");
    fake.answer(
        &[
            "/usr/bin/firewall-cmd",
            "--permanent",
            "--query-port",
            "18424/tcp",
        ],
        0,
        "yes\n",
    );
    fake.answer(
        &["/usr/bin/firewall-cmd", "--permanent", "--remove-port"],
        0,
        "success\n",
    );
    fake.answer(&["/usr/bin/firewall-cmd", "--reload"], 0, "success\n");
    fake.answer(&["/usr/bin/dnf", "remove"], 0, "");
    let plan = plan(&[Ingest, Distribution]);
    let ctx = fake.ctx(&plan);
    let args = args(&[Distribution], None);
    for step in RemoveStep::ALL {
        let state = run(&ctx, step, &args);
        assert!(state.finished(), "{step:?}: {state:?}");
    }
    assert_eq!(
        fake.call(&["/usr/bin/systemctl", "disable"]),
        [
            "/usr/bin/systemctl",
            "disable",
            "--now",
            "openvibes-distribution.service"
        ]
    );
    assert_eq!(
        fake.call(&["/usr/bin/firewall-cmd", "--permanent", "--remove-port"])[3],
        "18424/tcp"
    );
    assert_eq!(
        fake.call(&["/usr/bin/dnf"]),
        ["/usr/bin/dnf", "remove", "-y", "openvibes-distribution"]
    );
    assert!(!fake.called(&PG), "keep data: the database is not touched");
}

#[test]
fn removing_the_console_also_stops_the_fetch_socket_when_installed() {
    // An offline-kit host has the console but no fetcher (no socket).
    for fetch in [true, false] {
        let fake = Fake::new(&format!("remove-console-fetch-{fetch}"));
        let mut installed = vec!["openvibes-console"];
        if fetch {
            installed.push("openvibes-fetch");
        }
        for package in installed {
            fake.answer(&["/usr/bin/rpm", "-q", "--quiet", package], 0, "");
        }
        fake.answer(&["/usr/bin/systemctl", "disable", "--now"], 0, "");
        let plan = plan(&[Ingest, Console]);
        let state = run(&fake.ctx(&plan), RemoveStep::Stop, &args(&[Console], None));
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
        let call = fake.call(&["/usr/bin/systemctl", "disable"]);
        assert_eq!(
            call.contains(&"openvibes-fetch.socket".to_owned()),
            fetch,
            "{call:?}"
        );
    }
}

#[test]
fn the_admin_package_is_left_for_last() {
    let fake = Fake::new("remove-admin");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet"], 0, "");
    fake.answer(&["/usr/bin/dnf", "remove"], 0, "");
    let plan = plan(&[Ingest, Agent]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Packages,
        &args(&[Ingest, Agent], None),
    );
    assert_eq!(
        fake.call(&["/usr/bin/dnf"]),
        [
            "/usr/bin/dnf",
            "remove",
            "-y",
            "openvibes-ingest",
            "openvibes-agent"
        ]
    );
    assert!(!state.detail().contains("sudo"), "{state:?}");
}

#[test]
fn purge_needs_the_hostname_and_the_whole_platform() {
    let fake = Fake::new("purge-refused");
    fake.file("/etc/openvibes/setup.toml", "kept");
    let plan = plan(&[Ingest, Vulns]);
    let ctx = fake.ctx(&plan);
    assert!(matches!(
        run(&ctx, RemoveStep::Purge, &args(&[Ingest, Vulns], None)),
        StepState::Skipped(_)
    ));
    let wrong = run(
        &ctx,
        RemoveStep::Purge,
        &args(&[Ingest, Vulns], Some("other.example.com")),
    );
    assert!(wrong.detail().contains("does not match"), "{wrong:?}");
    let partial = run(
        &ctx,
        RemoveStep::Purge,
        &args(&[Vulns], Some("platform.example.com")),
    );
    assert!(partial.detail().contains("whole platform"), "{partial:?}");
    assert!(fake.root.join("etc/openvibes/setup.toml").exists());
    assert!(!fake.called(&PG));
}

#[test]
fn purge_drops_the_database_roles_files_and_accounts() {
    let fake = Fake::new("purge");
    fake.file("/etc/openvibes/setup.toml", "x");
    fake.file("/var/lib/openvibes-ingest/intermediate.key", "x");
    fake.file("/etc/openvibes-agent/agent.toml", "x");
    fake.answer(
        &[&PG[..], &["/usr/bin/psql"]].concat(),
        0,
        "openvibes-admin\nopenvibes-ingest\nopenvibes-console\n",
    );
    fake.answer(&[&PG[..], &["/usr/bin/dropdb"]].concat(), 0, "");
    fake.answer(&[&PG[..], &["/usr/bin/dropuser"]].concat(), 0, "");
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    let plan = plan(&[Ingest, Console]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Purge,
        &args(&[Ingest, Console], Some("platform.example.com")),
    );
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(fake.called(&[&PG[..], &["/usr/bin/dropdb", "--if-exists", "openvibes"]].concat()));
    let dropped: Vec<String> = fake
        .calls
        .borrow()
        .iter()
        .filter(|c| c.get(4).is_some_and(|p| p == "/usr/bin/dropuser"))
        .map(|c| c[6].clone())
        .collect();
    assert_eq!(
        dropped,
        ["openvibes-admin", "openvibes-ingest", "openvibes-console"]
    );
    for gone in ["var/lib/openvibes-ingest", "etc/openvibes-agent"] {
        assert!(!fake.root.join(gone).exists(), "{gone}");
    }
    // The plan stays until the last step, so a retry can still load it.
    assert_eq!(fake.text("/etc/openvibes/setup.toml"), "x");
    assert!(fake.called(&["/usr/sbin/userdel", "openvibes-ingest"]));
    assert!(fake.called(&["/usr/sbin/userdel", "openvibes-fetch"]));
    assert!(fake.called(&["/usr/sbin/groupdel", "openvibes-operators"]));
    assert!(
        state
            .detail()
            .contains("Setup has no record of installing PostgreSQL"),
        "{state:?}"
    );
}

/// Review 2026-10-10 (user: nothing may be left behind): every account
/// a platform package creates is one Uninstall deletes.
#[test]
fn every_packaged_service_account_is_deleted() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/rpm");
    let mut packaged = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "sysusers") {
            for line in std::fs::read_to_string(&path).unwrap().lines() {
                if let Some(rest) = line.strip_prefix("u ") {
                    packaged.push(rest.split_whitespace().next().unwrap().to_owned());
                }
            }
        }
    }
    assert!(packaged.len() >= 7, "{packaged:?}");
    for account in &packaged {
        assert!(
            super::ACCOUNTS.contains(&account.as_str()),
            "{account} is left behind"
        );
    }
}

/// #82: while openvibes-admin is still installed, its packaged
/// admin.toml stays for `dnf remove`; everything else goes.
#[test]
fn purge_leaves_the_admin_package_config_for_rpm() {
    let fake = Fake::new("purge-keep");
    fake.file("/etc/openvibes/admin.toml", "x");
    fake.file("/etc/openvibes/setup.toml", "x");
    fake.file("/etc/openvibes/tls/server.pem", "x");
    fake.file("/etc/openvibes/backup.toml", "folder = \"/home/a\"\n");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-admin"], 0, "");
    fake.answer(
        &["/usr/bin/rpm", "-qc", "openvibes-admin"],
        0,
        "/etc/openvibes/admin.toml\n",
    );
    fake.answer(&[&PG[..], &["/usr/bin/psql"]].concat(), 0, "");
    fake.answer(&[&PG[..], &["/usr/bin/dropdb"]].concat(), 0, "");
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    let plan = plan(&[Ingest]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Purge,
        &args(&[Ingest], Some("platform.example.com")),
    );
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(fake.root.join("etc/openvibes/admin.toml").exists());
    assert!(fake.root.join("etc/openvibes/setup.toml").exists());
    assert!(!fake.root.join("etc/openvibes/tls").exists());
    assert!(
        !fake.root.join("etc/openvibes/backup.toml").exists(),
        "the remembered backup folder goes with Remove everything"
    );
}

#[test]
fn a_wrong_confirmation_stops_every_step() {
    let fake = Fake::new("remove-wrong-name");
    let plan = plan(&[Ingest]);
    for step in RemoveStep::ALL {
        let state = run(
            &fake.ctx(&plan),
            step,
            &args(&[Ingest], Some("other.example.com")),
        );
        assert!(
            state.detail().contains("does not match"),
            "{step:?}: {state:?}"
        );
    }
    assert!(fake.calls.borrow().is_empty(), "nothing ran");
}

#[path = "remove_pg_tests.rs"]
mod pg_tests;
#[path = "remove_admin_tests.rs"]
mod admin_tests;

#[test]
fn remove_everything_refuses_a_backup_into_a_folder_it_removes() {
    // Review C1: the dump was written, then deleted with the folder.
    for folder in ["/var/backups/openvibes", "/etc/openvibes/old", "/var/lib/openvibes-vulns"] {
        let mut everything = args(&[Ingest], Some("platform.example.com"));
        everything.backup = Some(folder.into());
        let error = everything.check().unwrap_err();
        assert!(error.contains("Remove everything removes"), "{folder}: {error}");
        let mut keep = args(&[Ingest], None);
        keep.backup = Some(folder.into());
        assert_eq!(keep.check(), Ok(()), "Keep the data keeps {folder}");
    }
    let mut elsewhere = args(&[Ingest], Some("platform.example.com"));
    elsewhere.backup = Some("/var/backups/openvibes-old".into());
    assert_eq!(elsewhere.check(), Ok(()));
}

#[test]
fn a_half_done_remove_everything_is_never_finished_as_keep_the_data() {
    // Review I3: the mark says which uninstall it was.
    let fake = Fake::new("remove-mode-mark");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-ingest"], 0, "");
    fake.answer(&["/usr/bin/systemctl", "disable", "--now"], 0, "");
    let plan = plan(&[Ingest]);
    let everything = args(&[Ingest], Some("platform.example.com"));
    let state = run(&fake.ctx(&plan), RemoveStep::Stop, &everything);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    let mark = std::fs::read_to_string(fake.root.join("run/openvibes-admin/job")).unwrap();
    assert_eq!(mark, "uninstall\neverything");
    let calls = fake.calls.borrow().len();
    let keep = run(&fake.ctx(&plan), RemoveStep::Stop, &args(&[Ingest], None));
    assert!(
        matches!(&keep, StepState::Failed(why) if why.contains("Remove everything is half done")),
        "{keep:?}"
    );
    assert_eq!(fake.calls.borrow().len(), calls, "nothing ran");
    let again = run(&fake.ctx(&plan), RemoveStep::Stop, &everything);
    assert!(matches!(again, StepState::Done(_)), "{again:?}");
}
