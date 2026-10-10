//! Remove steps against the fake runner.
use platform_host::{RemoveStep, StepState};

use super::{RemoveArgs, run};
use crate::setup::{
    fake::{Fake, plan},
    plan::Component::{self, *},
};

const PG: [&str; 4] = ["/usr/sbin/runuser", "-u", "postgres", "--"];

fn args(components: &[Component], confirm: Option<&str>) -> RemoveArgs {
    RemoveArgs {
        components: components.to_vec(),
        backup: None,
        confirm: confirm.map(str::to_owned),
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
    assert!(
        state.detail().contains("sudo dnf remove openvibes-admin"),
        "{state:?}"
    );
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
    for gone in [
        "etc/openvibes",
        "var/lib/openvibes-ingest",
        "etc/openvibes-agent",
    ] {
        assert!(!fake.root.join(gone).exists(), "{gone}");
    }
    assert!(fake.called(&["/usr/sbin/userdel", "openvibes-ingest"]));
    assert!(fake.called(&["/usr/sbin/userdel", "openvibes-fetch"]));
    assert!(fake.called(&["/usr/sbin/groupdel", "openvibes-operators"]));
    assert!(
        state.detail().contains("PostgreSQL itself stays"),
        "{state:?}"
    );
}

/// #82: while openvibes-admin is still installed, its packaged
/// admin.toml stays for `dnf remove`; everything else goes.
#[test]
fn purge_leaves_the_admin_package_config_for_rpm() {
    let fake = Fake::new("purge-keep");
    fake.file("/etc/openvibes/admin.toml", "x");
    fake.file("/etc/openvibes/setup.toml", "x");
    fake.file("/etc/openvibes/tls/server.pem", "x");
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
    assert!(!fake.root.join("etc/openvibes/setup.toml").exists());
    assert!(!fake.root.join("etc/openvibes/tls").exists());
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
