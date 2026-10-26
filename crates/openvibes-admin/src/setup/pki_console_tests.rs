//! The certificates step with your own console certificate.

use std::os::unix::fs::PermissionsExt;

use chrono::Utc;
use platform_host::{Step, StepState};

use super::{OWN_CERT, OWN_KEY};
use crate::setup::{
    check,
    fake::{Fake, plan},
    pki::INTERMEDIATE,
    pki_tests::{ADMIN, certificate, installed_certificates, issuing, with},
    plan::Component::*,
    run_step,
};

const NAMES: [&str; 4] = ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"];
const CHAIN: &str = "/etc/openvibes/tls/console-chain.pem";
const KEY: &str = "/etc/openvibes/tls/console-key.pem";
const SERVER: &str = include_str!("../../../platform-pki/tests/fixtures/server.crt");
const SERVER_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/server.key");
const ISSUING: &str = include_str!("../../../platform-pki/tests/fixtures/issuing.crt");

fn mode(fake: &Fake, abs: &str) -> u32 {
    let path = fake.root.join(abs.trim_start_matches('/'));
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Your own pair, kept and installed as the console's.
fn own(fake: &Fake, cert: &str, key: &str) {
    fake.file(OWN_CERT, cert);
    fake.file(OWN_KEY, key);
    fake.file(CHAIN, cert);
    fake.file(KEY, key);
}

/// Where each `ca issue-server` wrote.
fn issued_to(fake: &Fake) -> Vec<String> {
    let issue = with(&ADMIN, &["ca", "issue-server"]);
    fake.calls
        .borrow()
        .iter()
        .filter(|call| call.iter().zip(&issue).all(|(a, b)| a == b) && call.len() > issue.len())
        .map(|call| call[call.iter().position(|a| a == "--out").unwrap() + 1].clone())
        .collect()
}

#[test]
fn renewal_leaves_your_own_console_certificate() {
    let fake = issuing("own-renewal");
    installed_certificates(&fake, &NAMES, 20);
    // Yours ends soon too: you renew it, not the timer.
    let yours = certificate(&NAMES, 20);
    own(&fake, &yours, "OWN KEY");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    let plan = plan(&[Ingest, Console, Distribution]);
    assert_eq!(check(&fake.ctx(&plan), Step::Certificates), StepState::Todo);
    let state = run_step(&fake.ctx(&plan), Step::Certificates);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(state.detail().contains("your own"), "{state:?}");
    assert_eq!(
        issued_to(&fake),
        ["/run/openvibes-ca/ingest", "/run/openvibes-ca/distribution"]
    );
    assert_eq!(fake.text(CHAIN), yours);
    assert_eq!(fake.text(KEY), "OWN KEY");
    assert!(
        fake.call(&["/usr/bin/systemctl", "try-restart"])
            .contains(&"openvibes-console".to_owned())
    );
}

#[test]
fn own_console_is_not_signed_by_the_intermediate_and_that_is_fine() {
    let fake = Fake::new("own-not-signed");
    let root = platform_pki::generate_root(Utc::now()).unwrap();
    let (csr, key) = platform_pki::intermediate_request().unwrap();
    let intermediate = platform_pki::sign_intermediate(&root, &csr, Utc::now()).unwrap();
    fake.file(INTERMEDIATE, &intermediate);
    let issuer = platform_pki::Issuer::load(&intermediate, &key).unwrap();
    let names: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
    for (cert, key) in [
        ("ingest.crt", "ingest.key"),
        ("distribution.crt", "distribution.key"),
    ] {
        let pem = issuer.issue_server(&names, Utc::now()).unwrap().cert_pem;
        fake.file(&format!("/etc/openvibes/tls/{cert}"), &pem);
        fake.file(&format!("/etc/openvibes/tls/{key}"), "KEY");
    }
    fake.file(
        "/etc/openvibes/tls/setup-names",
        &format!("{}\n", NAMES.join("\n")),
    );
    // Yours: from another CA, and 10 days left.
    let yours = certificate(&NAMES, 10);
    own(&fake, &yours, "OWN KEY");
    let plan = plan(&[Ingest, Console, Distribution]);
    let state = check(&fake.ctx(&plan), Step::Certificates);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    // Not your key installed, then not your certificate: Todo.
    fake.file(KEY, "OTHER KEY");
    assert_eq!(check(&fake.ctx(&plan), Step::Certificates), StepState::Todo);
    fake.file(KEY, "OWN KEY");
    fake.file(CHAIN, &certificate(&NAMES, 60));
    assert_eq!(check(&fake.ctx(&plan), Step::Certificates), StepState::Todo);
    // The same as text with CRLF: the same certificate.
    fake.file(CHAIN, &yours.replace('\n', "\r\n"));
    assert!(matches!(
        check(&fake.ctx(&plan), Step::Certificates),
        StepState::Done(_)
    ));
    // Without yours kept, the console's must come from the intermediate.
    fake.remove(OWN_CERT);
    fake.remove(OWN_KEY);
    assert_eq!(check(&fake.ctx(&plan), Step::Certificates), StepState::Todo);
}

#[test]
fn apply_installs_your_own_with_the_console_modes() {
    let fake = issuing("own-apply");
    let yours = format!("{SERVER}{ISSUING}");
    fake.file(OWN_CERT, &yours);
    fake.file(OWN_KEY, SERVER_KEY);
    std::fs::set_permissions(
        fake.root.join(OWN_KEY.trim_start_matches('/')),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    let plan = plan(&[Ingest, Console]);
    let state = run_step(&fake.ctx(&plan), Step::Certificates);
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert_eq!(issued_to(&fake), ["/run/openvibes-ca/ingest"]);
    assert_eq!(fake.text("/etc/openvibes/tls/ingest.crt"), "ingest CERT\n");
    assert_eq!(fake.text(CHAIN), yours);
    assert_eq!(fake.text(KEY), SERVER_KEY);
    assert_eq!(mode(&fake, CHAIN), 0o644);
    assert_eq!(mode(&fake, KEY), 0o640);
    assert_eq!(mode(&fake, OWN_KEY), 0o600);
    // Your key lost: a plain sentence, and the console's pair untouched.
    fake.remove(OWN_KEY);
    let state = run_step(&fake.ctx(&plan), Step::Certificates);
    assert!(
        matches!(&state, StepState::Failed(e) if e.contains("console-own.key is missing")),
        "{state:?}"
    );
    assert_eq!(fake.text(CHAIN), yours);
}
