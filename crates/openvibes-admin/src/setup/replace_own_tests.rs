//! Replacing the intermediate while the console uses your own certificate:
//! only the agents' certificates come from the new intermediate.

use super::{
    replace,
    tests::{careful_request, installed, intermediate},
};
use crate::setup::{
    fake::{Fake, plan},
    pki_console::{MISMATCH, OWN_CERT, OWN_KEY},
    plan::{CaMode, Component::*},
};

const YOURS: &str = include_str!("../../../platform-pki/tests/fixtures/server.crt");
const KEY: &str = include_str!("../../../platform-pki/tests/fixtures/server.key");

/// Your own pair, as `console-cert-set` and the certificates step leave it.
fn own_pair(fake: &Fake, cert: &str, key: &str) {
    for (file, text) in [
        (OWN_CERT, cert),
        (OWN_KEY, key),
        ("/etc/openvibes/tls/console-chain.pem", cert),
        ("/etc/openvibes/tls/console-key.pem", key),
    ] {
        fake.file(file, text);
    }
}

#[test]
fn replace_keeps_your_own_console_certificate() {
    let (fake, root, _) = installed("replace-own");
    let new = intermediate(&root);
    careful_request(&fake, &new.0, &new.1, &root.cert_pem);
    own_pair(&fake, YOURS, KEY);
    let mut plan = plan(&[Ingest, Console, Distribution]);
    plan.ca = CaMode::Careful;
    replace(&fake.ctx(&plan), None).unwrap();
    // Only the agents' certificates come from the new intermediate.
    let outs: Vec<String> = fake
        .calls
        .borrow()
        .iter()
        .filter(|call| call.contains(&"issue-server".to_owned()))
        .map(|call| call[call.iter().position(|a| a == "--out").unwrap() + 1].clone())
        .collect();
    assert_eq!(
        outs,
        ["/run/openvibes-ca/ingest", "/run/openvibes-ca/distribution"]
    );
    assert_eq!(fake.text("/etc/openvibes/tls/console-chain.pem"), YOURS);
    assert_eq!(fake.text("/etc/openvibes/tls/console-key.pem"), KEY);
}

#[test]
fn a_broken_own_pair_says_the_agents_certificates_were_reissued() {
    let (fake, root, _) = installed("replace-own-broken");
    let new = intermediate(&root);
    careful_request(&fake, &new.0, &new.1, &root.cert_pem);
    let other = include_str!("../../../platform-pki/tests/fixtures/ours-ec.pkcs8.pem");
    own_pair(&fake, YOURS, other);
    let mut plan = plan(&[Ingest, Console, Distribution]);
    plan.ca = CaMode::Careful;
    let error = replace(&fake.ctx(&plan), None).unwrap_err();
    assert!(
        error.starts_with(
            "The intermediate was replaced and the agents' certificates reissued, but the \
             console's own certificate was not installed: "
        ),
        "{error}"
    );
    assert!(error.ends_with(MISMATCH), "{error}");
    assert!(!error.contains("were not reissued"), "{error}");
}
