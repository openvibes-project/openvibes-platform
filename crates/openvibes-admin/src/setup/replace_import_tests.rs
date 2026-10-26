//! Replacing an imported intermediate (sub-project 4b): the next one from
//! the same PKI, staged by `ca-import`, under the same root; `chain.crt`
//! moves with the bundle and the key.

use super::{FAIL_RENAME, PREVIOUS, PREVIOUS_UNTIL, replace, tests::certificates};
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

const CHAIN_OLD: &str = "/etc/openvibes/pki/chain.crt.old";
/// No swap file is left: not the `.new` ones, not the chain's copy.
const SWAP_FILES: [&str; 6] = [
    PREVIOUS,
    PREVIOUS_UNTIL,
    "/etc/openvibes/pki/intermediate.crt.new",
    "/var/lib/openvibes-ingest/intermediate.key.new",
    "/etc/openvibes/pki/chain.crt.new",
    CHAIN_OLD,
];

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
    for left in SWAP_FILES {
        assert!(!exists(&fake, left), "{left}");
    }

    // Tried again with the way clear: no chain.crt any more.
    std::fs::remove_dir(fake.root.join(&INTERMEDIATE_KEY[1..])).unwrap();
    fake.file(INTERMEDIATE_KEY, OLD_KEY);
    replace(&fake.ctx(&import_plan()), None).unwrap();
    assert_eq!(certificates(&fake.text(INTERMEDIATE)).len(), 2);
    assert_eq!(fake.text(INTERMEDIATE_KEY), STRICT_KEY);
    assert!(!exists(&fake, CHAIN));
    for left in [CHAIN_OLD, "/etc/openvibes/pki/chain.crt.new"] {
        assert!(!exists(&fake, left), "{left}");
    }
}

/// The old pair, its chain `chain` (`None`: no chain.crt) and no swap file.
fn unchanged(fake: &Fake, chain: Option<&str>) {
    assert_eq!(fake.text(INTERMEDIATE), OLD);
    assert_eq!(fake.text(INTERMEDIATE_KEY), OLD_KEY);
    match chain {
        Some(chain) => assert_eq!(fake.text(CHAIN), chain),
        None => assert!(!exists(fake, CHAIN)),
    }
    for left in SWAP_FILES {
        assert!(!exists(fake, left), "{left}");
    }
}

#[test]
fn a_failed_chain_rename_puts_the_old_pair_back() {
    let fake = imported("replace-import-chain-fails", OURS, OURS_KEY, ISSUING);
    let old_chain = format!("{ISSUING}{ISSUING}");
    fake.file(CHAIN, &old_chain);
    FAIL_RENAME.set(Some(CHAIN));
    let error = replace(&fake.ctx(&import_plan()), None).unwrap_err();
    FAIL_RENAME.set(None);
    assert!(error.contains("refused by the test"), "{error}");
    unchanged(&fake, Some(&old_chain));
}

#[test]
fn a_rollback_removes_a_chain_that_was_not_there() {
    let fake = imported("replace-import-no-old-chain", OURS, OURS_KEY, ISSUING);
    fake.remove(CHAIN);
    FAIL_RENAME.set(Some(INTERMEDIATE_KEY));
    assert!(replace(&fake.ctx(&import_plan()), None).is_err());
    FAIL_RENAME.set(None);
    unchanged(&fake, None);
}

#[test]
fn an_unreadable_chain_stops_the_swap_first() {
    let fake = imported("replace-import-chain-unreadable", OURS, OURS_KEY, ISSUING);
    fake.remove(CHAIN);
    std::fs::create_dir(fake.root.join(&CHAIN[1..])).unwrap();
    let error = replace(&fake.ctx(&import_plan()), None).unwrap_err();
    assert!(error.starts_with(CHAIN), "{error}");
    assert_eq!(fake.text(INTERMEDIATE), OLD);
    assert!(!exists(&fake, PREVIOUS));
}

#[test]
fn an_undo_puts_the_chain_back_from_its_copy() {
    // Both faults: the old bundle went back, the old chain did not.
    for (copy, chain) in [
        (format!("{ISSUING}{ISSUING}"), Some(())),
        (String::new(), None),
    ] {
        let fake = imported("replace-import-undo", OURS, OURS_KEY, ISSUING);
        fake.file(PREVIOUS, OLD);
        fake.file(
            PREVIOUS_UNTIL,
            &format!("{}\n", chrono::Utc::now().to_rfc3339()),
        );
        fake.file("/var/lib/openvibes-ingest/intermediate.key.new", OURS_KEY);
        fake.file("/etc/openvibes/pki/chain.crt.new", ISSUING);
        fake.file(CHAIN_OLD, &copy);
        assert_eq!(
            super::finish_interrupted(&fake.ctx(&import_plan())),
            Ok(Some(
                "removed an interrupted replacement that never took effect".into()
            ))
        );
        unchanged(&fake, chain.map(|()| copy.as_str()));
    }
}

#[test]
fn replace_refuses_the_intermediate_in_use() {
    let fake = imported("replace-import-in-use", OLD, OLD_KEY, ISSUING);
    assert_eq!(
        replace(&fake.ctx(&import_plan()), None).unwrap_err(),
        "This is the intermediate already in use: ask your PKI for a new one."
    );
    unchanged(&fake, Some(ISSUING));
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
