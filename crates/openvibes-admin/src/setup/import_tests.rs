//! `helper ca-import` on a temp root, with the platform-pki fixtures.

use std::os::unix::fs::PermissionsExt;

use chrono::{DateTime, TimeZone, Utc};
use platform_pki::{ChainError, PkiError};

use super::{IMPORT_DIR, MAX, import, import_message, imported, read_bundle};
use crate::setup::{
    fake::{Fake, plan},
    pki::{INTERMEDIATE, INTERMEDIATE_KEY, ROOT_CERT},
    plan::Component::Ingest,
};

const ROOT: &str = include_str!("../../../platform-pki/tests/fixtures/root.crt");
const ISSUING: &str = include_str!("../../../platform-pki/tests/fixtures/issuing.crt");
const OURS: &str = include_str!("../../../platform-pki/tests/fixtures/ours-ec.crt");
const OURS_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/ours-ec.pkcs8.pem");
const RSA_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/ours-rsa.key");
const STRICT: &str = include_str!("../../../platform-pki/tests/fixtures/strict.crt");
const STRICT_KEY: &str = include_str!("../../../platform-pki/tests/fixtures/strict.key");

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2027, 6, 1, 0, 0, 0).unwrap()
}

fn staged(name: &str) -> String {
    format!("{IMPORT_DIR}/{name}")
}

fn mode(fake: &Fake, abs: &str) -> u32 {
    std::fs::metadata(fake.root.join(abs.trim_start_matches('/')))
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn full() -> String {
    format!("{OURS}{ISSUING}{ROOT}{OURS_KEY}")
}

#[test]
fn stages_the_three_files_and_the_key() {
    let fake = Fake::new("import-stages");
    let plan = plan(&[Ingest]);
    let chain = import(&fake.ctx(&plan), &full(), now()).unwrap();
    assert_eq!(
        imported(&chain),
        "imported\tLime Lab OpenVIBES CA\tLime Lab Issuing CA › Lime Lab Root CA\t2046-01-01\n"
    );
    assert_eq!(fake.text(&staged("intermediate.crt")), OURS);
    assert_eq!(fake.text(&staged("chain.crt")), ISSUING);
    assert_eq!(fake.text(&staged("root.crt")), ROOT);
    assert!(
        fake.text(&staged("intermediate.key"))
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );
    assert_eq!(mode(&fake, IMPORT_DIR), 0o700);
    assert_eq!(mode(&fake, &staged("intermediate.key")), 0o600);
    for name in ["intermediate.crt", "chain.crt", "root.crt"] {
        assert_eq!(mode(&fake, &staged(name)), 0o644, "{name}");
    }
}

#[test]
fn the_key_is_written_first() {
    let fake = Fake::new("import-key-first");
    let plan = plan(&[Ingest]);
    // The certificate's place is taken, so its write fails.
    std::fs::create_dir_all(
        fake.root
            .join(staged("intermediate.crt").trim_start_matches('/')),
    )
    .unwrap();
    assert!(import(&fake.ctx(&plan), &full(), now()).is_err());
    assert!(
        fake.text(&staged("intermediate.key"))
            .contains("PRIVATE KEY")
    );
}

#[test]
fn refuses_and_writes_nothing() {
    let fake = Fake::new("import-refuses");
    let plan = plan(&[Ingest]);
    let error = import(
        &fake.ctx(&plan),
        &format!("{OURS}{ISSUING}{ROOT}{RSA_KEY}"),
        now(),
    )
    .unwrap_err();
    assert_eq!(
        error,
        "Not the key of Lime Lab OpenVIBES CA: paste the key it was made with."
    );
    assert!(!fake.root.join(IMPORT_DIR.trim_start_matches('/')).exists());
}

#[test]
fn an_installed_ca_needs_the_same_root() {
    let fake = Fake::new("import-same-root");
    let plan = plan(&[Ingest]);
    let other = platform_pki::generate_root(Utc::now()).unwrap();
    fake.file(INTERMEDIATE, OURS);
    fake.file(INTERMEDIATE_KEY, OURS_KEY);
    fake.file(ROOT_CERT, &other.cert_pem);
    assert_eq!(
        import(&fake.ctx(&plan), &full(), now()).unwrap_err(),
        "Replace: under Lime Lab Root CA, not OpenVIBES Root CA, so agents would stop \
         trusting this host. Ask for one under the same root."
    );
    assert!(!fake.root.join(IMPORT_DIR.trim_start_matches('/')).exists());
    fake.file(ROOT_CERT, &format!("\n{ROOT}\n"));
    assert!(import(&fake.ctx(&plan), &full(), now()).is_ok());
}

#[test]
fn chain_is_left_out_when_there_is_none() {
    let fake = Fake::new("import-no-chain");
    let plan = plan(&[Ingest]);
    import(&fake.ctx(&plan), &full(), now()).unwrap();
    let chain = import(
        &fake.ctx(&plan),
        &format!("{STRICT}{ROOT}{STRICT_KEY}"),
        now(),
    )
    .unwrap();
    assert_eq!(chain.path, ["Lime Lab Root CA"]);
    assert_eq!(fake.text(&staged("intermediate.crt")), STRICT);
    // The chain of an earlier import does not stay behind.
    assert!(
        !fake
            .root
            .join(staged("chain.crt").trim_start_matches('/'))
            .exists()
    );
}

#[test]
fn a_bundle_is_certificates_then_one_key() {
    let fake = Fake::new("import-bundle");
    let plan = plan(&[Ingest]);
    let ctx = fake.ctx(&plan);
    let two_keys = format!("{}{OURS_KEY}", full());
    let after = format!("{OURS}{ISSUING}{OURS_KEY}{ROOT}");
    let other = format!(
        "{OURS}{ISSUING}{ROOT}-----BEGIN RSA PRIVATE KEY-----\nAA\n-----END RSA PRIVATE KEY-----\n"
    );
    for (bundle, why) in [
        (format!("{OURS}{ISSUING}{ROOT}"), "no private key"),
        (two_keys, "one private key"),
        (after, "the key last"),
        (other, "RSA PRIVATE KEY"),
        ("-----BEGIN CERTIFICATE-----\nAA\n".into(), "no END line"),
    ] {
        let error = import(&ctx, &bundle, now()).unwrap_err();
        assert!(error.contains(why), "{error}");
        assert!(!error.contains("MIG"), "{error}");
    }
}

#[test]
fn the_bundle_is_at_most_one_mib() {
    let text = read_bundle(&mut "x".repeat(MAX).as_bytes()).unwrap();
    assert_eq!(text.len(), MAX);
    assert_eq!(
        read_bundle(&mut "x".repeat(MAX + 1).as_bytes()).unwrap_err(),
        "The certificate and key are too large (over 1 MiB)."
    );
}

#[test]
fn every_refusal_has_its_sentence() {
    let day = Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap();
    let name = "Lime Lab OpenVIBES CA";
    let message = |e: ChainError| import_message(&e, name, None);
    assert_eq!(
        message(ChainError::NotCa("Web".into())),
        "Web is not a CA, so it cannot sign agent certificates."
    );
    assert_eq!(
        message(ChainError::Missing("Root".into())),
        "Signed by Root, missing here: paste it below this one."
    );
    assert_eq!(
        message(ChainError::IsRoot("Root".into())),
        "Root is a root CA: paste the intermediate made for OpenVIBES first, then the CAs above it."
    );
    assert_eq!(
        message(ChainError::NotYetValid(day)),
        "Valid from 2026-12-01: not valid yet."
    );
    assert_eq!(
        message(ChainError::NoCaBelow("Strict".into())),
        "Strict allows no CA below it: ask for one more level."
    );
    assert_eq!(
        message(ChainError::Expiring(day)),
        "Valid until 2026-12-01: under the 90 days a server certificate lasts."
    );
    assert_eq!(
        message(ChainError::InvalidPem),
        "This is not a certificate in PEM form (-----BEGIN CERTIFICATE-----)."
    );
    let pki = |e: PkiError| message(ChainError::Pki(e));
    assert_eq!(
        pki(PkiError::WeakKey(1024)),
        "A 1024-bit RSA key is too weak: 2048 bits or more."
    );
    assert_eq!(pki(PkiError::WrongPassword), "Wrong password.");
    assert_eq!(
        import_message(
            &ChainError::Pki(PkiError::WrongPassword),
            name,
            Some("ours.key")
        ),
        "Wrong password for ours.key."
    );
    assert_eq!(
        pki(PkiError::KeyMismatch),
        "Not the key of Lime Lab OpenVIBES CA: paste the key it was made with."
    );
    assert_eq!(
        pki(PkiError::NameMismatch),
        "OpenVIBES cannot reproduce Lime Lab OpenVIBES CA's name exactly, so its certificates \
         would not chain: ask for a certificate with a UTF-8 name."
    );
    assert_eq!(
        pki(PkiError::UnsupportedKey),
        "This key type is not supported: use RSA (2048 to 4096 bits), EC P-256 or P-384, or \
         Ed25519."
    );
    assert_eq!(
        pki(PkiError::KeyLocked),
        "The key is locked: give its password."
    );
    assert_eq!(
        pki(PkiError::OldEncryption),
        "This key's encryption is too old to open here: ask for it with AES."
    );
    assert_eq!(
        pki(PkiError::NotCa),
        "The certificate was refused: certificate is not a CA."
    );
}
