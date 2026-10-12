//! Remove steps against the fake runner.
use platform_host::{RemoveStep, StepState};

use super::{RemoveArgs, run};
use crate::setup::{
    fake::{Fake, plan},
    plan::Component::{self, *},
};

const GPG: &str = "gpg-pubkey-7786da36-6a0f1e07\tOpenVIBES packages <26064407+itismelime@users.noreply.github.com> public key\n\
                   gpg-pubkey-11111111-1\tFedora (44) <fedora-44-primary@fedoraproject.org> public key\n";

fn admin_answers(fake: &Fake, left: &str) {
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-admin"], 0, "");
    fake.answer(&["/usr/bin/dnf", "remove", "-y", "openvibes-admin"], 0, "");
    fake.answer(&["/usr/bin/rpm", "-qa", "openvibes-*"], 0, left);
    fake.answer(&["/usr/bin/rpm", "-q", "gpg-pubkey"], 0, GPG);
    fake.answer(&["/usr/bin/rpm", "-e"], 0, "");
}

const PG: [&str; 4] = ["/usr/sbin/runuser", "-u", "postgres", "--"];

fn args(components: &[Component], confirm: Option<&str>) -> RemoveArgs {
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
        state.detail().contains("PostgreSQL itself stays"),
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

#[test]
fn the_last_step_removes_the_tool_what_rpm_kept_and_the_repository() {
    let fake = Fake::new("remove-admin-last");
    fake.file("/etc/openvibes/setup.toml", "x");
    fake.file("/etc/openvibes/admin.toml.rpmsave", "x");
    fake.file("/etc/sudoers.d/openvibes-operators.rpmsave", "x");
    fake.file("/etc/sudoers.d/wheel", "not ours");
    fake.file("/var/lib/openvibes-admin/state", "x");
    fake.file("/etc/yum.repos.d/openvibes.repo", "[openvibes]\n");
    fake.file("/etc/yum.repos.d/fedora.repo", "[fedora]\n");
    fake.file("/etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes", "k");
    fake.file("/etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44", "k");
    fake.file("/var/cache/libdnf5/openvibes-0123456789abcdef/x", "c");
    fake.file("/var/cache/libdnf5/fedora-cff72538bc9825a4/x", "c");
    fake.file("/run/openvibes-admin/job", "uninstall");
    fake.file("/run/openvibes-admin/setup.lock", "");
    admin_answers(&fake, "");
    let plan = plan(&[Ingest, Agent]);
    let state = run(
        &fake.ctx(&plan),
        RemoveStep::Admin,
        &args(&[Ingest, Agent], Some("platform.example.com")),
    );
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    for gone in [
        "etc/openvibes",
        "var/lib/openvibes-admin",
        "etc/yum.repos.d/openvibes.repo",
        "etc/sudoers.d/openvibes-operators.rpmsave",
        "etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes",
        "var/cache/libdnf5/openvibes-0123456789abcdef",
        "run/openvibes-admin",
    ] {
        assert!(!fake.root.join(gone).exists(), "{gone} left behind");
    }
    for kept in [
        "etc/yum.repos.d/fedora.repo",
        "etc/sudoers.d/wheel",
        "etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-44",
        "var/cache/libdnf5/fedora-cff72538bc9825a4",
    ] {
        assert!(fake.root.join(kept).exists(), "{kept} is not ours");
    }
    assert_eq!(
        fake.call(&["/usr/bin/rpm", "-e"]),
        ["/usr/bin/rpm", "-e", "gpg-pubkey-7786da36-6a0f1e07"]
    );
    assert!(!fake.called(&["/usr/bin/rpm", "-e", "gpg-pubkey-11111111-1"]));
    assert!(
        state.detail().contains("closes"),
        "says what the user sees: {state:?}"
    );
}

#[test]
fn keep_data_removes_the_tool_and_keeps_the_configuration() {
    let fake = Fake::new("remove-admin-keep");
    fake.file("/etc/openvibes/setup.toml", "kept");
    fake.file("/var/lib/openvibes-admin/state", "kept");
    admin_answers(&fake, "");
    let plan = plan(&[Ingest]);
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest], None));
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(fake.called(&["/usr/bin/dnf", "remove", "-y", "openvibes-admin"]));
    assert_eq!(fake.text("/etc/openvibes/setup.toml"), "kept");
    assert_eq!(fake.text("/var/lib/openvibes-admin/state"), "kept");
    assert!(
        state.detail().contains("kept: /etc/openvibes"),
        "listed: {state:?}"
    );
}

#[test]
fn removing_one_part_leaves_the_administration_tool() {
    let fake = Fake::new("remove-admin-part");
    let plan = plan(&[Ingest, Agent]);
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Agent], None));
    assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
    assert!(!fake.called(&["/usr/bin/dnf"]));
}

#[test]
fn the_repository_stays_while_another_openvibes_package_is_installed() {
    let fake = Fake::new("remove-admin-agent-left");
    fake.file("/etc/yum.repos.d/openvibes.repo", "[openvibes]\n");
    admin_answers(&fake, "openvibes-agent\n");
    let plan = plan(&[Ingest]);
    run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest], None));
    assert!(fake.root.join("etc/yum.repos.d/openvibes.repo").exists());
    assert!(!fake.called(&["/usr/bin/rpm", "-e"]));
}

#[test]
fn purge_keeps_the_plan_so_the_last_step_can_load_it() {
    let fake = Fake::new("purge-keeps-plan");
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.file("/etc/openvibes/tls/server.pem", "x");
    fake.answer(&[&PG[..], &["/usr/bin/psql"]].concat(), 0, "");
    fake.answer(&[&PG[..], &["/usr/bin/dropdb"]].concat(), 0, "");
    fake.answer(&["/usr/sbin/userdel"], 0, "");
    fake.answer(&["/usr/sbin/groupdel"], 0, "");
    let plan = plan(&[Ingest]);
    let ctx = fake.ctx(&plan);
    let a = args(&[Ingest], Some("platform.example.com"));
    // Running it twice is safe: the second run finds the work done.
    for _ in 0..2 {
        let state = run(&ctx, RemoveStep::Purge, &a);
        assert!(matches!(state, StepState::Done(_)), "{state:?}");
    }
    assert_eq!(fake.text("/etc/openvibes/setup.toml"), "plan");
    assert!(!fake.root.join("etc/openvibes/tls").exists());
}

/// A failed key removal leaves the plan in place and the job marked, and
/// Try again on a host where the package is already gone finishes.
#[test]
fn a_failed_last_step_can_be_run_again() {
    let fake = Fake::new("remove-admin-retry");
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.file("/etc/yum.repos.d/openvibes.repo", "[openvibes]\n");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-admin"], 0, "");
    fake.answer(&["/usr/bin/dnf", "remove", "-y", "openvibes-admin"], 0, "");
    fake.answer(&["/usr/bin/rpm", "-qa", "openvibes-*"], 0, "");
    fake.answer(&["/usr/bin/rpm", "-q", "gpg-pubkey"], 0, GPG);
    fake.fail(&["/usr/bin/rpm", "-e"], "rpmdb locked");
    let plan = plan(&[Ingest]);
    let a = args(&[Ingest], Some("platform.example.com"));
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &a);
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(
        fake.root.join("etc/openvibes/setup.toml").exists(),
        "the plan is needed to retry"
    );

    // Second run: the package and the key are already gone.
    let again = Fake::new("remove-admin-retry-2");
    again.file("/etc/openvibes/setup.toml", "plan");
    again.answer(&["/usr/bin/rpm", "-qa", "openvibes-*"], 0, "");
    again.answer(
        &["/usr/bin/rpm", "-q", "gpg-pubkey"],
        1,
        "package gpg-pubkey is not installed\n",
    );
    let state = run(&again.ctx(&plan), RemoveStep::Admin, &a);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(!again.called(&["/usr/bin/dnf"]));
    assert!(!again.root.join("etc/openvibes").exists());
}

#[test]
fn a_failed_last_step_keeps_the_job_marked() {
    let fake = Fake::new("remove-admin-mark");
    fake.file("/run/openvibes-admin/job", "uninstall");
    fake.file("/etc/openvibes/setup.toml", "plan");
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-admin"], 0, "");
    fake.fail(&["/usr/bin/dnf", "remove"], "locked");
    let plan = plan(&[Ingest]);
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest], None));
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(fake.root.join("run/openvibes-admin/job").exists());
}
