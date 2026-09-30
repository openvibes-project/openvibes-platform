//! The CA and certificate steps against the fake runner.

use platform_host::{Step, StepState};

use crate::setup::{
    fake::{Fake, plan},
    plan::{CaMode, Component::*},
    run_step,
};

const ADMIN: [&str; 5] = [
    "/usr/sbin/runuser",
    "-u",
    "openvibes-admin",
    "--",
    "/usr/bin/openvibes-admin",
];

fn with(prefix: &[&str], rest: &[&str]) -> Vec<&'static str> {
    prefix
        .iter()
        .chain(rest)
        .map(|s| &*Box::leak((*s).to_owned().into_boxed_str()))
        .collect()
}

/// The CA commands as fakes that write what the real ones write.
fn ca_commands(fake: &Fake) {
    fake.effect(&["/usr/bin/openvibes-admin", "ca", "init-root"], |root| {
        let dir = root.join("run/openvibes-ca/root");
        std::fs::create_dir_all(&dir).unwrap();
        let ca = platform_pki::generate_root(chrono::Utc::now()).unwrap();
        std::fs::write(dir.join("root.crt"), &ca.cert_pem).unwrap();
        std::fs::write(dir.join("root.key"), &ca.key_pem).unwrap();
    });
    fake.effect(&with(&ADMIN, &["ca", "intermediate-request"]), |root| {
        let dir = root.join("run/openvibes-ca/int");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("intermediate.csr"), "CSR").unwrap();
        std::fs::write(dir.join("intermediate.key"), "INTERMEDIATE KEY").unwrap();
    });
    fake.effect(
        &["/usr/bin/openvibes-admin", "ca", "sign-intermediate"],
        |root| {
            std::fs::write(
                root.join("run/openvibes-ca/int/intermediate.crt"),
                "INTERMEDIATE",
            )
            .unwrap();
        },
    );
    fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 0, "");
}

#[test]
fn quick_ca_keeps_only_the_root_certificate_and_the_chosen_key_copy() {
    let fake = Fake::new("ca-quick");
    ca_commands(&fake);
    fake.file("/run/openvibes-ca/stale", "left by a failed run");
    let mut plan = plan(&[Ingest]);
    plan.root_key_out = Some("/media/usb/openvibes-root.key".into());
    std::fs::create_dir_all(fake.root.join("media/usb")).unwrap();
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(
        state.detail().contains("/media/usb/openvibes-root.key"),
        "{state:?}"
    );
    assert!(state.detail().contains("SHA-256 "), "{state:?}");
    assert!(
        fake.text("/etc/openvibes/pki/root.crt")
            .contains("BEGIN CERTIFICATE")
    );
    assert_eq!(
        fake.text("/etc/openvibes/pki/intermediate.crt"),
        "INTERMEDIATE"
    );
    assert_eq!(
        fake.text("/var/lib/openvibes-ingest/intermediate.key"),
        "INTERMEDIATE KEY"
    );
    assert!(
        fake.text("/media/usb/openvibes-root.key")
            .contains("PRIVATE KEY")
    );
    assert!(
        !fake.root.join("run/openvibes-ca").exists(),
        "staging removed"
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = |abs: &str| {
        std::fs::metadata(fake.root.join(abs.trim_start_matches('/')))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("/var/lib/openvibes-ingest/intermediate.key"), 0o600);
    assert_eq!(mode("/media/usb/openvibes-root.key"), 0o600);
    assert_eq!(mode("/etc/openvibes/pki/root.crt"), 0o644);
    // Done now: a second run changes nothing.
    let calls = fake.calls.borrow().len();
    assert!(matches!(
        run_step(&fake.ctx(&plan), Step::Ca),
        StepState::Done(_)
    ));
    assert_eq!(fake.calls.borrow().len(), calls);
}

#[test]
fn a_stale_staging_directory_is_replaced() {
    let fake = Fake::new("ca-stale");
    ca_commands(&fake);
    fake.file(
        "/run/openvibes-ca/root/root.crt",
        "half-written by a failed run",
    );
    let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(state.detail().contains("root key deleted"), "{state:?}");
}

#[test]
fn a_failed_import_leaves_no_root_key_file_to_block_the_retry() {
    let fake = Fake::new("ca-import-fails");
    fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 1, "");
    ca_commands(&fake);
    std::fs::create_dir_all(fake.root.join("media/usb")).unwrap();
    let mut plan = plan(&[Ingest]);
    plan.root_key_out = Some("/media/usb/openvibes-root.key".into());
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(
        !fake.root.join("media/usb/openvibes-root.key").exists(),
        "a key for a root that was never installed would block every retry"
    );
}

#[test]
fn an_existing_root_key_file_is_not_overwritten() {
    let fake = Fake::new("ca-existing-key");
    ca_commands(&fake);
    fake.file("/media/usb/openvibes-root.key", "an older root key");
    let mut plan = plan(&[Ingest]);
    plan.root_key_out = Some("/media/usb/openvibes-root.key".into());
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert!(state.detail().contains("already exists"), "{state:?}");
    assert_eq!(
        fake.text("/media/usb/openvibes-root.key"),
        "an older root key"
    );
    assert!(
        !fake.called(&["/usr/bin/openvibes-admin", "ca", "init-root"]),
        "checked before any CA material"
    );
}

#[test]
fn careful_ca_waits_for_the_signed_certificate() {
    let fake = Fake::new("ca-careful");
    ca_commands(&fake);
    let mut plan = plan(&[Ingest]);
    plan.ca = CaMode::Careful;
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert!(matches!(state, StepState::Waiting(_)), "{state:?}");
    assert!(state.detail().contains("sign-intermediate"), "{state:?}");
    assert!(!fake.called(&["/usr/bin/openvibes-admin", "ca", "init-root"]));
    assert!(matches!(
        run_step(&fake.ctx(&plan), Step::Ca),
        StepState::Waiting(_)
    ));
    let root = platform_pki::generate_root(chrono::Utc::now()).unwrap();
    fake.file("/run/openvibes-ca/int/intermediate.crt", "INTERMEDIATE");
    fake.file("/run/openvibes-ca/int/root.crt", &root.cert_pem);
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(fake.called(&with(&ADMIN, &["ca", "import-intermediate"])));
}

#[test]
fn certificates_are_issued_for_every_name_and_installed() {
    let fake = Fake::new("certificates");
    fake.file("/etc/openvibes/pki/intermediate.crt", "INTERMEDIATE\n");
    fake.file(
        "/var/lib/openvibes-ingest/intermediate.key",
        "INTERMEDIATE KEY",
    );
    fake.effect(&with(&ADMIN, &["ca", "issue-server"]), |root| {
        for service in ["ingest", "distribution", "console"] {
            let dir = root.join(format!("run/openvibes-ca/{service}"));
            if dir.exists() && !dir.join("platform.example.com.crt").exists() {
                std::fs::write(
                    dir.join("platform.example.com.crt"),
                    format!("{service} CERT\n"),
                )
                .unwrap();
                std::fs::write(
                    dir.join("platform.example.com.key"),
                    format!("{service} KEY"),
                )
                .unwrap();
                return;
            }
        }
        panic!("no output directory");
    });
    let state = run_step(
        &fake.ctx(&plan(&[Ingest, Console, Distribution])),
        Step::Certificates,
    );
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    let issue = fake.call(&with(&ADMIN, &["ca", "issue-server"]));
    assert_eq!(
        issue[7..],
        [
            "platform.example.com",
            "--san",
            "10.0.0.5",
            "--san",
            "localhost",
            "--san",
            "127.0.0.1",
            "--issuer-cert",
            "/run/openvibes-ca/issuer.crt",
            "--issuer-key",
            "/run/openvibes-ca/issuer.key",
            "--out",
            "/run/openvibes-ca/ingest"
        ]
    );
    assert_eq!(fake.text("/etc/openvibes/tls/ingest.crt"), "ingest CERT\n");
    assert_eq!(
        fake.text("/etc/openvibes/tls/console-chain.pem"),
        "console CERT\nINTERMEDIATE\n"
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = |abs: &str| {
        std::fs::metadata(fake.root.join(abs.trim_start_matches('/')))
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode("/etc/openvibes/tls/ingest.key"), 0o600);
    assert_eq!(mode("/etc/openvibes/tls/distribution.key"), 0o600);
    assert_eq!(mode("/etc/openvibes/tls/console-key.pem"), 0o640);
    assert_eq!(mode("/etc/openvibes/tls/console-chain.pem"), 0o640);
    assert!(!fake.root.join("run/openvibes-ca").exists());
    assert_eq!(
        fake.text("/etc/openvibes/tls/setup-names"),
        "platform.example.com\n10.0.0.5\nlocalhost\n127.0.0.1\n"
    );
}

#[test]
fn repair_never_makes_a_new_ca() {
    let fake = Fake::new("ca-repair");
    ca_commands(&fake);
    let plan = plan(&[Ingest]);
    let mut ctx = fake.ctx(&plan);
    ctx.repair = true;
    let state = run_step(&ctx, Step::Ca);
    assert!(state.detail().contains("never makes a new CA"), "{state:?}");
    assert!(!fake.called(&["/usr/bin/openvibes-admin", "ca", "init-root"]));
}

/// A real certificate for NAMES, valid until NOW + DAYS.
fn certificate(names: &[&str], days_left: i64) -> String {
    let now = chrono::Utc::now();
    let root = platform_pki::generate_root(now - chrono::Duration::days(100)).unwrap();
    let issuer = platform_pki::Issuer::load(&root.cert_pem, &root.key_pem).unwrap();
    // Server certificates live 90 days.
    let issued = now - chrono::Duration::days(90 - days_left);
    let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
    issuer.issue_server(&names, issued).unwrap().cert_pem
}

fn installed_certificates(fake: &Fake, names: &[&str], days_left: i64) {
    for (cert, key) in [
        ("ingest.crt", "ingest.key"),
        ("distribution.crt", "distribution.key"),
    ] {
        fake.file(
            &format!("/etc/openvibes/tls/{cert}"),
            &certificate(names, days_left),
        );
        fake.file(&format!("/etc/openvibes/tls/{key}"), "KEY");
    }
    fake.file(
        "/etc/openvibes/tls/setup-names",
        &format!("{}\n", names.join("\n")),
    );
}

#[test]
fn certificates_for_other_names_are_issued_again() {
    let fake = Fake::new("certs-renamed");
    installed_certificates(
        &fake,
        &["old.example.com", "10.0.0.5", "localhost", "127.0.0.1"],
        60,
    );
    let state = crate::setup::check(
        &fake.ctx(&plan(&[Ingest, Distribution])),
        Step::Certificates,
    );
    assert_eq!(state, StepState::Todo);
}

#[test]
fn a_certificate_about_to_expire_is_reported_not_replaced() {
    let fake = Fake::new("certs-expiring");
    installed_certificates(
        &fake,
        &["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"],
        5,
    );
    let state = run_step(
        &fake.ctx(&plan(&[Ingest, Distribution])),
        Step::Certificates,
    );
    assert!(matches!(state, StepState::Failed(_)), "{state:?}");
    assert!(state.detail().contains("renew"), "{state:?}");
    assert!(!fake.called(&["/usr/sbin/runuser"]), "nothing re-issued");
    installed_certificates(
        &fake,
        &["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"],
        60,
    );
    assert!(matches!(
        run_step(
            &fake.ctx(&plan(&[Ingest, Distribution])),
            Step::Certificates
        ),
        StepState::Done(_)
    ));
}

#[test]
fn a_second_run_is_refused() {
    let fake = Fake::new("lock");
    let first = crate::setup::system::lock(&fake.root).unwrap();
    let second = crate::setup::system::lock(&fake.root).unwrap_err();
    assert!(second.contains("another Setup run"), "{second}");
    drop(first);
    assert!(crate::setup::system::lock(&fake.root).is_ok());
}

/// `ip -o addr show scope global` on a host with Wi-Fi, Ethernet, IPv6
/// (a stable and a rotating privacy address) and container bridges.
const IP_ADDR: &str = "\
2: enp5s0    inet 192.168.1.10/24 brd 192.168.1.255 scope global dynamic noprefixroute enp5s0\\       valid_lft 54853sec preferred_lft 54853sec
3: wlp4s0    inet 192.168.1.181/24 brd 192.168.1.255 scope global dynamic noprefixroute wlp4s0\\       valid_lft 51670sec preferred_lft 51670sec
4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever
5: podman0    inet 10.88.0.1/16 brd 10.88.255.255 scope global podman0\\       valid_lft forever preferred_lft forever
6: virbr0    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0\\       valid_lft forever preferred_lft forever
8: lxdbr0    inet 10.10.10.1/24 brd 10.10.10.255 scope global lxdbr0\\       valid_lft forever preferred_lft forever
9: wg0    inet 10.66.0.1/24 scope global wg0\\       valid_lft forever preferred_lft forever
7: enp6s0    inet 10.0.0.5/24 brd 10.0.0.255 scope global enp6s0\\       valid_lft forever preferred_lft forever
2: enp5s0    inet6 2001:db8:0:1::10/64 scope global dynamic mngtmpaddr noprefixroute \\       valid_lft 86000sec preferred_lft 14000sec
2: enp5s0    inet6 2001:db8:0:1:a1b2:c3d4:e5f6:1234/64 scope global temporary dynamic \\       valid_lft 86000sec preferred_lft 14000sec
2: enp5s0    inet6 2001:db8:0:1::99/64 scope global deprecated dynamic \\       valid_lft 600sec preferred_lft 0sec
4: docker0    inet6 fd00:dead::1/64 scope global \\       valid_lft forever preferred_lft forever
";

/// Board #71: the console opens by the host's IP over a VPN, so the
/// certificate names its LAN addresses too, not container bridges'.
#[test]
fn certificates_also_name_the_hosts_own_addresses() {
    let fake = Fake::new("cert-host-ips");
    fake.answer(
        &["/usr/sbin/ip", "-o", "addr", "show", "scope", "global"],
        0,
        IP_ADDR,
    );
    installed_certificates(
        &fake,
        &["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"],
        60,
    );
    let state = super::check(
        &fake.ctx(&plan(&[Ingest, Distribution])),
        Step::Certificates,
    );
    assert_eq!(
        state,
        StepState::Todo,
        "a new address needs a new certificate"
    );
    let names = super::pki::certificate_names(&fake.ctx(&plan(&[Ingest])));
    assert_eq!(
        names,
        [
            "platform.example.com",
            "10.0.0.5",
            "localhost",
            "127.0.0.1",
            "192.168.1.10",
            "192.168.1.181",
            "10.66.0.1",
            "2001:db8:0:1::10",
        ]
    );
}

#[test]
fn without_ip_the_certificate_keeps_the_planned_names() {
    let fake = Fake::new("cert-no-ip");
    let names = super::pki::certificate_names(&fake.ctx(&plan(&[Ingest])));
    assert_eq!(
        names,
        ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"]
    );
}
