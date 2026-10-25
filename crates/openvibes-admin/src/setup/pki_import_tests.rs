//! The CA step for Import from your PKI, and the chain in the server
//! certificates, against the fake runner and the platform-pki fixtures.

use std::os::unix::fs::PermissionsExt;

use platform_host::{Step, StepState};

use super::CHAIN;
use crate::setup::{
    check,
    fake::{Fake, plan},
    import::IMPORT_DIR,
    pki::{INTERMEDIATE, INTERMEDIATE_KEY, ROOT_CERT},
    pki_tests::{ADMIN, certificate, installed_certificates, issuing, with},
    plan::{CaMode, Component::*, Plan, plan_of},
    run_step,
};

const ROOT: &str = include_str!("../../../platform-pki/tests/fixtures/root.crt");
const ISSUING: &str = include_str!("../../../platform-pki/tests/fixtures/issuing.crt");
const OURS: &str = include_str!("../../../platform-pki/tests/fixtures/ours-ec.crt");
const OURS_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/ours-ec.pkcs8.pem");

const HELP: &str = "add the certificate and its key from your PKI: Install › Certificates";

fn import_plan() -> Plan {
    Plan {
        ca: CaMode::Import,
        ..plan(&[Ingest])
    }
}

fn mode(fake: &Fake, abs: &str) -> u32 {
    std::fs::metadata(fake.root.join(abs.trim_start_matches('/')))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn exists(fake: &Fake, abs: &str) -> bool {
    fake.root.join(abs.trim_start_matches('/')).exists()
}

/// What `ca-import` stages for a three-level PKI.
fn staged(fake: &Fake) {
    fake.file(&format!("{IMPORT_DIR}/intermediate.key"), OURS_KEY);
    fake.file(&format!("{IMPORT_DIR}/intermediate.crt"), OURS);
    fake.file(&format!("{IMPORT_DIR}/chain.crt"), ISSUING);
    fake.file(&format!("{IMPORT_DIR}/root.crt"), ROOT);
}

#[test]
fn import_installs_from_the_staging() {
    let fake = Fake::new("import-installs");
    staged(&fake);
    fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 0, "");
    let state = run_step(&fake.ctx(&import_plan()), Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(state.detail().contains("SHA-256 "), "{state:?}");
    let call = fake.call(&with(&ADMIN, &["ca", "import-intermediate"]));
    assert_eq!(
        call[7..],
        [
            "--cert",
            "/run/openvibes-ca/int/intermediate.crt",
            "--key",
            "/run/openvibes-ca/int/intermediate.key",
            "--root-cert",
            "/run/openvibes-ca/int/root.crt",
            "--chain",
            "/run/openvibes-ca/int/chain.crt",
        ]
    );
    assert_eq!(fake.text(INTERMEDIATE), OURS, "ours only, never the chain");
    assert_eq!(fake.text(ROOT_CERT), ROOT);
    assert_eq!(fake.text(CHAIN), ISSUING);
    assert_eq!(fake.text(INTERMEDIATE_KEY), OURS_KEY);
    for public in [INTERMEDIATE, ROOT_CERT, CHAIN] {
        assert_eq!(mode(&fake, public), 0o644, "{public}");
    }
    assert_eq!(mode(&fake, INTERMEDIATE_KEY), 0o600);
}

#[test]
fn import_staging_is_removed_after_install() {
    let fake = Fake::new("import-cleans");
    staged(&fake);
    fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 0, "");
    let state = run_step(&fake.ctx(&import_plan()), Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(!exists(&fake, IMPORT_DIR), "the key's staged copy is gone");
    assert!(!exists(&fake, "/run/openvibes-ca"));
    // Done now: a second run changes nothing.
    let calls = fake.calls.borrow().len();
    assert!(matches!(
        run_step(&fake.ctx(&import_plan()), Step::Ca),
        StepState::Done(_)
    ));
    assert_eq!(fake.calls.borrow().len(), calls);
}

#[test]
fn a_two_level_pki_installs_no_chain() {
    let fake = Fake::new("import-two-level");
    staged(&fake);
    fake.remove(&format!("{IMPORT_DIR}/chain.crt"));
    fake.file(CHAIN, "left from an earlier install");
    fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 0, "");
    let state = run_step(&fake.ctx(&import_plan()), Step::Ca);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    // Still the chain check (any path length), with nothing in between.
    let call = fake.call(&with(&ADMIN, &["ca", "import-intermediate"]));
    assert_eq!(call[13..], ["--chain", "/run/openvibes-ca/int/chain.crt"]);
    assert!(!exists(&fake, CHAIN), "a stale chain is removed");
}

#[test]
fn import_waits_until_staged() {
    let fake = Fake::new("import-waits");
    let plan = import_plan();
    assert_eq!(
        check(&fake.ctx(&plan), Step::Ca),
        StepState::Waiting(HELP.into())
    );
    // Half staged (no root yet) is not enough either.
    fake.file(&format!("{IMPORT_DIR}/intermediate.key"), OURS_KEY);
    fake.file(&format!("{IMPORT_DIR}/intermediate.crt"), OURS);
    let state = run_step(&fake.ctx(&plan), Step::Ca);
    assert_eq!(state, StepState::Waiting(HELP.into()));
    assert!(fake.calls.borrow().is_empty(), "{:?}", fake.calls.borrow());
}

#[test]
fn repair_never_imports_over_an_installed_ca() {
    let fake = Fake::new("import-repair");
    fake.file(INTERMEDIATE, OURS);
    fake.file(ROOT_CERT, ROOT);
    fake.file(INTERMEDIATE_KEY, OURS_KEY);
    staged(&fake);
    let plan = import_plan();
    let mut ctx = fake.ctx(&plan);
    ctx.repair = true;
    assert!(matches!(check(&ctx, Step::Ca), StepState::Done(_)));
    let state = super::super::pki::ca_apply(&ctx).unwrap();
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(!fake.called(&with(&ADMIN, &["ca", "import-intermediate"])));
    assert_eq!(fake.text(&format!("{IMPORT_DIR}/root.crt")), ROOT);
    assert_eq!(
        fake.text(&format!("{IMPORT_DIR}/intermediate.key")),
        OURS_KEY
    );
}

#[test]
fn server_certificates_end_in_the_chain() {
    let fake = issuing("import-issue-chain");
    fake.file(CHAIN, ISSUING);
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    let state = run_step(&fake.ctx(&plan(&[Ingest])), Step::Certificates);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    let issue = fake.call(&with(&ADMIN, &["ca", "issue-server"]));
    assert_eq!(issue[issue.len() - 2..], ["--chain", CHAIN]);
}

#[test]
fn certificates_check_wants_the_chain() {
    let fake = Fake::new("import-check-chain");
    let names = ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"];
    installed_certificates(&fake, &names, 60);
    let plan = plan(&[Ingest, Distribution]);
    assert!(matches!(
        check(&fake.ctx(&plan), Step::Certificates),
        StepState::Done(_)
    ));
    // A chain installed since (or changed): issued again so they end in it.
    fake.file(CHAIN, ISSUING);
    assert_eq!(check(&fake.ctx(&plan), Step::Certificates), StepState::Todo);
    for cert in ["ingest.crt", "distribution.crt"] {
        let chained = format!("{}{ISSUING}", certificate(&names, 60));
        fake.file(&format!("/etc/openvibes/tls/{cert}"), &chained);
    }
    assert!(matches!(
        check(&fake.ctx(&plan), Step::Certificates),
        StepState::Done(_)
    ));
}

#[test]
fn the_plan_says_import() {
    let plan = plan_of("components = [\"ingest\"]\nhostname = \"h\"\nca = \"import\"").unwrap();
    assert_eq!(plan.ca, CaMode::Import);
    let text = toml::to_string(&import_plan()).unwrap();
    assert!(text.contains("ca = \"import\""), "{text}");
}

#[test]
fn a_chain_written_by_hand_still_matches() {
    let fake = Fake::new("import-chain-by-hand");
    let names = ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"];
    installed_certificates(&fake, &names, 60);
    for cert in ["ingest.crt", "distribution.crt"] {
        let chained = format!("{}{ISSUING}", certificate(&names, 60));
        fake.file(&format!("/etc/openvibes/tls/{cert}"), &chained);
    }
    // As `openssl pkcs12 -nokeys` writes it: attributes around the block,
    // and CRLF line ends.
    let by_hand = format!(
        "Bag Attributes\r\nsubject=CN=Lime Lab Issuing CA\r\nissuer=CN=Lime Lab Root CA\r\n{}",
        ISSUING.replace('\n', "\r\n")
    );
    fake.file(CHAIN, &by_hand);
    let plan = plan(&[Ingest, Distribution]);
    let state = check(&fake.ctx(&plan), Step::Certificates);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
}
