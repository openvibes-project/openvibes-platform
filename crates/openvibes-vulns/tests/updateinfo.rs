//! Fedora `updateinfo.xml` parsing against a trimmed real Fedora 44 file.

use std::{fs::File, io::BufReader, path::PathBuf};

use openvibes_vulns::updateinfo::{self, Advisory, ParseError, Severity};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn parse(name: &str) -> Vec<Advisory> {
    let file = BufReader::new(File::open(fixture(name)).unwrap());
    updateinfo::read(file, 1 << 20).unwrap()
}

#[test]
fn only_security_advisories_are_kept() {
    let ids: Vec<String> = parse("updateinfo-f44.xml")
        .into_iter()
        .map(|a| a.id)
        .collect();
    assert_eq!(
        ids,
        [
            "FEDORA-2026-2c6e5be623",
            "FEDORA-2026-dc0ff85b8b",
            "FEDORA-2026-9781489c3a"
        ],
        "the bugfix update is dropped"
    );
}

#[test]
fn cves_come_from_references_and_the_description() {
    let advisories = parse("updateinfo-f44.xml");
    assert_eq!(advisories[0].cves, ["CVE-2026-18536"]);
    assert_eq!(
        advisories[1].cves,
        ["CVE-2026-64638", "CVE-2026-65640"],
        "only named in the description"
    );
}

#[test]
fn severities_and_metadata() {
    let advisories = parse("updateinfo-f44.xml");
    let severities: Vec<Severity> = advisories.iter().map(|a| a.severity).collect();
    assert_eq!(
        severities,
        [Severity::Low, Severity::Important, Severity::Unrated]
    );
    assert!(!advisories[0].title.is_empty());
    assert!(advisories[0].issued.starts_with("2026-"));
    assert_eq!(
        advisories[0].url(),
        "https://bodhi.fedoraproject.org/updates/FEDORA-2026-2c6e5be623"
    );
}

#[test]
fn fixed_packages_exclude_sources() {
    let advisories = parse("updateinfo-f44.xml");
    let wordpress: Vec<(&str, &str)> = advisories[1]
        .packages
        .iter()
        .map(|p| (p.name.as_str(), p.arch.as_str()))
        .collect();
    assert_eq!(wordpress, [("wordpress", "noarch")]);
    let agent = &advisories[2].packages;
    assert_eq!(agent.len(), 6, "binary packages for x86_64 and aarch64");
    let first = &agent[0];
    assert_eq!(
        (first.epoch, first.version.as_str(), first.release.as_str()),
        (0, "20260717.00", "1.fc44")
    );
}

#[test]
fn zstd_compressed_input_is_read() {
    let file = BufReader::new(File::open(fixture("updateinfo-f44.xml.zst")).unwrap());
    let advisories = updateinfo::read_zstd(file, 1 << 20).unwrap();
    assert_eq!(advisories.len(), 3);
}

#[test]
fn input_over_the_size_cap_is_refused() {
    let file = BufReader::new(File::open(fixture("updateinfo-f44.xml")).unwrap());
    assert_eq!(
        updateinfo::read(file, 1024).unwrap_err(),
        ParseError::TooLarge
    );
    let junk = BufReader::new(&b"<updates><update type=\"security\"><id>"[..]);
    assert!(matches!(
        updateinfo::read(junk, 1 << 20),
        Err(ParseError::Malformed)
    ));
}
