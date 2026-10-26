//! `helper console-cert-set` and `console-cert-reset` on a temp root.

use std::os::unix::fs::PermissionsExt;

use chrono::Utc;
use platform_pki::{PkiError, ServerCertError};

use super::{console_cert_message, reset, set};
use crate::setup::{
    fake::{Fake, plan},
    pki_console::{OWN_CERT, OWN_KEY},
    pki_tests::{installed_certificates, issuing},
    plan::Component::*,
};

const SERVER: &str = include_str!("../../../platform-pki/tests/fixtures/server.crt");
const SERVER_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/server.key");
const OTHER_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/short.key");
const ISSUING: &str = include_str!("../../../platform-pki/tests/fixtures/issuing.crt");
const EXPIRED: &str = include_str!("../../../platform-pki/tests/fixtures/server-expired.crt");
const CHAIN: &str = "/etc/openvibes/tls/console-chain.pem";
const KEY: &str = "/etc/openvibes/tls/console-key.pem";

fn mode(fake: &Fake, abs: &str) -> u32 {
    let path = fake.root.join(abs.trim_start_matches('/'));
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn restarted(fake: &Fake) -> bool {
    fake.called(&["/usr/bin/systemctl", "try-restart"])
}

#[test]
fn set_keeps_the_pair_and_installs_it() {
    let fake = issuing("cert-set");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    let plan = plan(&[Ingest, Console]);
    let bundle = format!("{SERVER}{ISSUING}{SERVER_KEY}");
    let line = set(&fake.ctx(&plan), &bundle, Utc::now()).unwrap();
    assert!(line.starts_with("set\t"), "{line}");
    assert!(
        line.ends_with('\n') && line.matches('\t').count() == 2,
        "{line}"
    );
    assert_eq!(fake.text(OWN_KEY), SERVER_KEY);
    assert_eq!(fake.text(OWN_CERT), format!("{SERVER}{ISSUING}"));
    assert_eq!(
        (mode(&fake, OWN_KEY), mode(&fake, OWN_CERT)),
        (0o600, 0o644)
    );
    assert_eq!(fake.text(CHAIN), fake.text(OWN_CERT));
    assert_eq!(fake.text(KEY), SERVER_KEY);
    assert!(restarted(&fake));
}

#[test]
fn set_refuses_and_writes_nothing() {
    let plan = plan(&[Ingest, Console]);
    for (test, bundle, said) in [
        (
            "ca",
            format!("{ISSUING}{SERVER_KEY}"),
            "This is a CA certificate",
        ),
        ("expired", format!("{EXPIRED}{SERVER_KEY}"), "Expired on "),
        (
            "key",
            format!("{SERVER}{OTHER_KEY}"),
            "Not the key of this certificate",
        ),
        ("nokey", SERVER.to_owned(), "holds no private key"),
    ] {
        let fake = issuing(&format!("cert-refuse-{test}"));
        let error = set(&fake.ctx(&plan), &bundle, Utc::now()).unwrap_err();
        assert!(error.contains(said), "{test}: {error}");
        assert!(!fake.root.join("etc/openvibes/tls").exists(), "{test}");
        assert!(!restarted(&fake), "{test}");
    }
}

#[test]
fn a_step_that_fails_keeps_the_pair() {
    let fake = issuing("cert-step-fails");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 1, "");
    let plan = plan(&[Ingest, Console]);
    let bundle = format!("{SERVER}{SERVER_KEY}");
    let error = set(&fake.ctx(&plan), &bundle, Utc::now()).unwrap_err();
    assert!(error.starts_with("The certificate is kept, but"), "{error}");
    assert_eq!(fake.text(OWN_KEY), SERVER_KEY);
}

#[test]
fn reset_reissues_the_platforms() {
    let fake = issuing("cert-reset");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    let plan = plan(&[Ingest, Console]);
    let names = ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"];
    installed_certificates(&fake, &names, 60);
    // Nothing of yours: nothing to do, nothing restarted.
    assert_eq!(reset(&fake.ctx(&plan)).unwrap(), "reset\n");
    assert!(!restarted(&fake));
    let bundle = format!("{SERVER}{SERVER_KEY}");
    set(&fake.ctx(&plan), &bundle, Utc::now()).unwrap();
    assert_eq!(fake.text(CHAIN), SERVER);
    // The fake issuer wrote text, not certificates, for the agents.
    installed_certificates(&fake, &names, 60);
    assert_eq!(reset(&fake.ctx(&plan)).unwrap(), "reset\n");
    assert!(!fake.root.join(OWN_CERT.trim_start_matches('/')).exists());
    assert!(!fake.root.join(OWN_KEY.trim_start_matches('/')).exists());
    assert_eq!(fake.text(CHAIN), "console CERT\n");
    assert_eq!(fake.text(KEY), "console KEY");
}

#[test]
fn the_key_never_reaches_argv_or_journal() {
    let fake = issuing("cert-no-key");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    let plan = plan(&[Ingest, Console]);
    let bundle = format!("{SERVER}{OTHER_KEY}");
    let error = set(&fake.ctx(&plan), &bundle, Utc::now()).unwrap_err();
    let ok = format!("{SERVER}{SERVER_KEY}");
    let line = set(&fake.ctx(&plan), &ok, Utc::now()).unwrap();
    let body: String = SERVER_KEY.lines().nth(1).unwrap().into();
    let seen = format!("{:?}{error}{line}", fake.calls.borrow());
    assert!(!seen.contains(&body) && !seen.contains("PRIVATE"), "{seen}");
    assert!(fake.inputs.borrow().iter().all(|i| !i.contains(&body)));
}

#[test]
fn the_sentences() {
    let day = Utc::now();
    let say = |e| console_cert_message(&e, Some("c.p12"));
    assert_eq!(
        say(ServerCertError::NotForServers),
        "Not for servers (its extended key usage): ask for a server certificate."
    );
    assert_eq!(
        say(ServerCertError::CoversNone),
        "Covers none of this console's names: add one under Names first."
    );
    assert_eq!(
        say(ServerCertError::NotYetValid(day)),
        format!("Valid from {}: not valid yet.", day.format("%F"))
    );
    assert_eq!(
        say(ServerCertError::Pki(PkiError::WrongPassword)),
        "Wrong password for c.p12."
    );
}
