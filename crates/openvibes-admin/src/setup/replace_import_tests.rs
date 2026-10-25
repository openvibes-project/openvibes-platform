//! Replacing an imported intermediate (sub-project 4b): the next one from
//! the same PKI, staged by `ca-import`, under the same root; `chain.crt`
//! moves with the bundle and the key.

use super::{PREVIOUS, PREVIOUS_UNTIL, replace, tests::certificates};
use crate::setup::{
    fake::{Fake, plan},
    import::IMPORT_DIR,
    pki::{INTERMEDIATE, INTERMEDIATE_KEY, ROOT_CERT},
    pki_import::CHAIN,
    pki_tests::{ADMIN, issuing, with},
    plan::{CaMode, Component::*, Plan},
    request::REQUEST_DIR,
};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("../../../platform-pki/tests/fixtures/", $name))
    };
}
const ROOT: &str = fixture!("root.crt");
const ISSUING: &str = fixture!("issuing.crt");
const OURS: &str = fixture!("ours-ec.crt");
const OURS_KEY: &str = fixture!("ours-ec.pkcs8.pem");
const OLD: &str = fixture!("ours-rsa.crt");
const OLD_KEY: &str = fixture!("ours-rsa.key");
/// Directly under the root: a two-level PKI, no `chain.crt`.
const STRICT: &str = fixture!("strict.crt");
const STRICT_KEY: &str = fixture!("strict.key");

fn import_plan() -> Plan {
    Plan {
        ca: CaMode::Import,
        ..plan(&[Ingest])
    }
}

fn exists(fake: &Fake, abs: &str) -> bool {
    fake.root.join(abs.trim_start_matches('/')).exists()
}

/// A host that imported `OLD` under issuing, then `ca-import` staged
/// `cert` and `key` (with `chain`, when not empty).
fn imported(test: &str, cert: &str, key: &str, chain: &str) -> Fake {
    let fake = issuing(test);
    fake.file(ROOT_CERT, ROOT);
    fake.file(INTERMEDIATE, OLD);
    fake.file(INTERMEDIATE_KEY, OLD_KEY);
    fake.file(CHAIN, ISSUING);
    fake.answer(&with(&ADMIN, &["ca", "import-intermediate"]), 0, "");
    fake.answer(&["/usr/bin/systemctl", "try-restart"], 0, "");
    fake.file(&format!("{IMPORT_DIR}/intermediate.key"), key);
    fake.file(&format!("{IMPORT_DIR}/intermediate.crt"), cert);
    if !chain.is_empty() {
        fake.file(&format!("{IMPORT_DIR}/chain.crt"), chain);
    }
    fake.file(&format!("{IMPORT_DIR}/root.crt"), ROOT);
    fake
}

#[test]
fn replace_installs_the_imported_one() {
    let fake = imported("replace-import", OURS, OURS_KEY, ISSUING);
    replace(&fake.ctx(&import_plan()), None).unwrap();
    let bundle = certificates(&fake.text(INTERMEDIATE));
    assert_eq!(bundle.len(), 2);
    assert_eq!(bundle[0], platform_pki::first_certificate(OURS).unwrap());
    assert_eq!(bundle[1], platform_pki::first_certificate(OLD).unwrap());
    assert_eq!(fake.text(PREVIOUS), bundle[1]);
    assert_eq!(fake.text(INTERMEDIATE_KEY), OURS_KEY);
    assert_eq!(fake.text(CHAIN), ISSUING);
    let import = fake.call(&with(&ADMIN, &["ca", "import-intermediate"]));
    assert_eq!(
        import[7..],
        [
            "--cert",
            "/run/openvibes-ca/int/intermediate.crt",
            "--key",
            "/run/openvibes-ca/int/intermediate.key",
            "--root-cert",
            ROOT_CERT,
            "--chain",
            "/run/openvibes-ca/int/chain.crt",
        ]
    );
    // Reissued at once with the new chain; the import is gone.
    let issued = fake.call(&with(&ADMIN, &["ca", "issue-server"]));
    assert!(issued.contains(&CHAIN.to_owned()), "{issued:?}");
    assert!(!exists(&fake, REQUEST_DIR));
    assert!(!exists(&fake, "/run/openvibes-ca"));
    assert!(!exists(&fake, &format!("{CHAIN}.new")));
}

#[test]
fn replace_refuses_another_root_staged() {
    let fake = imported("replace-import-root", OURS, OURS_KEY, ISSUING);
    let other = platform_pki::generate_root(chrono::Utc::now()).unwrap();
    fake.file(ROOT_CERT, &other.cert_pem);
    let error = replace(&fake.ctx(&import_plan()), None).unwrap_err();
    assert!(
        error.starts_with("Replace: under Lime Lab Root CA, not ")
            && error.ends_with(
                ", so agents would stop trusting this host. Ask for one under the same root."
            ),
        "{error}"
    );
    assert_eq!(fake.text(INTERMEDIATE), OLD);
    assert_eq!(fake.text(CHAIN), ISSUING);
    assert!(!exists(&fake, PREVIOUS));
    assert!(!fake.called(&with(&ADMIN, &["ca", "import-intermediate"])));
}

#[test]
fn replace_with_nothing_imported_says_so() {
    let fake = imported("replace-import-none", OURS, OURS_KEY, ISSUING);
    fake.remove(&format!("{IMPORT_DIR}/intermediate.key"));
    assert_eq!(
        replace(&fake.ctx(&import_plan()), None).unwrap_err(),
        "There is nothing imported: add the certificate and its key first."
    );
    assert_eq!(fake.text(INTERMEDIATE), OLD);
}

#[test]
fn swap_moves_the_chain_and_rolls_back() {
    // Two-level next: the old chain.crt goes only once the swap is done.
    let fake = imported("replace-import-swap", STRICT, STRICT_KEY, "");
    // The key cannot be renamed into place: a folder is in the way, after
    // the bundle and the chain were renamed.
    fake.remove(INTERMEDIATE_KEY);
    std::fs::create_dir(fake.root.join(&INTERMEDIATE_KEY[1..])).unwrap();
    assert!(replace(&fake.ctx(&import_plan()), None).is_err());
    assert_eq!(fake.text(INTERMEDIATE), OLD);
    assert_eq!(fake.text(CHAIN), ISSUING);
    for left in [
        PREVIOUS.to_owned(),
        PREVIOUS_UNTIL.to_owned(),
        format!("{CHAIN}.new"),
        format!("{INTERMEDIATE}.new"),
    ] {
        assert!(!exists(&fake, &left), "{left}");
    }

    // Tried again with the way clear: no chain.crt any more.
    std::fs::remove_dir(fake.root.join(&INTERMEDIATE_KEY[1..])).unwrap();
    fake.file(INTERMEDIATE_KEY, OLD_KEY);
    replace(&fake.ctx(&import_plan()), None).unwrap();
    assert_eq!(certificates(&fake.text(INTERMEDIATE)).len(), 2);
    assert_eq!(fake.text(INTERMEDIATE_KEY), STRICT_KEY);
    assert!(!exists(&fake, CHAIN));
    assert!(!exists(&fake, &format!("{CHAIN}.new")));
}

#[test]
fn an_interrupted_swap_finishes_with_its_chain() {
    // Crashed after the bundle was renamed: the chain and key are left.
    let fake = imported("replace-import-crash", OURS, OURS_KEY, ISSUING);
    let other_chain = format!("{ISSUING}{ISSUING}");
    fake.file(CHAIN, &other_chain);
    fake.file(INTERMEDIATE, &format!("{OURS}{OLD}"));
    fake.file(PREVIOUS, OLD);
    fake.file(
        PREVIOUS_UNTIL,
        &format!("{}\n", chrono::Utc::now().to_rfc3339()),
    );
    fake.file(&format!("{INTERMEDIATE_KEY}.new"), OURS_KEY);
    fake.file(&format!("{CHAIN}.new"), ISSUING);
    assert_eq!(
        super::finish_interrupted(&fake.ctx(&import_plan())),
        Ok(Some("finished an interrupted replacement".into()))
    );
    assert_eq!(fake.text(CHAIN), ISSUING);
    assert_eq!(fake.text(INTERMEDIATE_KEY), OURS_KEY);
    // An empty one stood for "no chain": removed.
    fake.file(CHAIN, "");
    fake.file(&format!("{INTERMEDIATE_KEY}.new"), OURS_KEY);
    super::finish_interrupted(&fake.ctx(&import_plan())).unwrap();
    assert!(!exists(&fake, CHAIN));
}

#[test]
fn ca_import_refuses_the_old_key_with_the_next_certificate() {
    let fake = imported("replace-import-old-key", OURS, OURS_KEY, ISSUING);
    fake.remove(&format!("{IMPORT_DIR}/intermediate.key"));
    let bundle = format!("{OURS}{ISSUING}{ROOT}{OLD_KEY}");
    let error =
        crate::setup::import::import(&fake.ctx(&import_plan()), &bundle, chrono::Utc::now())
            .unwrap_err();
    assert_eq!(
        error,
        "Not the key of Lime Lab OpenVIBES CA: paste the key it was made with."
    );
    assert!(!exists(&fake, &format!("{IMPORT_DIR}/intermediate.key")));
}
