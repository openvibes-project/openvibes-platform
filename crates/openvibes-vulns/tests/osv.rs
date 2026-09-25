//! OSV records from Rocky, AlmaLinux, Debian and Ubuntu, parsed from
//! trimmed real records (2026-09-25).

use std::path::PathBuf;

use openvibes_vulns::osv::{self, Release};

fn record(name: &str) -> osv::Record {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/osv")
        .join(format!("{name}.json"));
    osv::parse(&std::fs::read(path).unwrap()).unwrap()
}

fn release(name: &str) -> Release {
    name.parse().unwrap()
}

#[test]
fn rocky_advisory_for_its_release_with_epochs() {
    let rocky = record("RLSA-2019_0975");
    let advisory = osv::advisory(&rocky, &release("rocky-8")).unwrap();
    assert_eq!(advisory.advisory_id, "RLSA-2019:0975/rocky-8");
    assert_eq!(advisory.severity, "important", "from the title");
    assert_eq!(advisory.cves, ["CVE-2019-5736"]);
    assert_eq!(advisory.url, "https://osv.dev/vulnerability/RLSA-2019:0975");
    let packages: Vec<(&str, &str, Option<&str>)> = advisory
        .packages
        .iter()
        .map(|p| (p.name.as_str(), p.scheme.as_str(), p.fixed.as_deref()))
        .collect();
    assert_eq!(
        packages,
        [
            (
                "oci-systemd-hook",
                "rpm",
                Some("1:0.1.15-2.git2d0b8a3.module+el8.4.0+557+48ba8b2f")
            ),
            (
                "oci-umount",
                "rpm",
                Some("2:2.3.4-2.git87f9237.module+el8.4.0+557+48ba8b2f")
            ),
        ]
    );
    assert!(
        osv::advisory(&rocky, &release("rocky-9")).is_none(),
        "an 8 advisory"
    );
    assert_eq!(
        advisory.packages[0].match_on, "source",
        "Rocky names source RPMs"
    );
}

#[test]
fn alma_takes_cves_from_related_and_severity_from_the_title() {
    let alma = record("ALSA-2026_71419");
    let advisory = osv::advisory(&alma, &release("almalinux-10")).unwrap();
    assert_eq!(advisory.severity, "critical");
    assert_eq!(
        advisory.cves,
        ["CVE-2026-81634", "CVE-2026-81642", "CVE-2026-82717"]
    );
    assert_eq!(
        advisory.packages.len(),
        7,
        "unbound and its six subpackages"
    );
    assert_eq!(
        advisory.packages[0].match_on, "binary",
        "Alma names binaries"
    );
}

#[test]
fn debian_matches_source_packages_per_release() {
    let binutils = record("DEBIAN-CVE-2005-4808");
    for name in ["debian-12", "debian-13"] {
        let advisory = osv::advisory(&binutils, &release(name)).unwrap();
        assert_eq!(advisory.advisory_id, format!("DEBIAN-CVE-2005-4808/{name}"));
        assert_eq!(advisory.cves, ["CVE-2005-4808"], "from upstream");
        assert_eq!(advisory.severity, "low", "urgency low");
        let package = &advisory.packages[0];
        assert_eq!(
            (
                package.name.as_str(),
                package.scheme.as_str(),
                package.match_on.as_str(),
                package.fixed.as_deref()
            ),
            ("binutils", "dpkg", "source", Some("2.17-1"))
        );
    }
    // No fix yet: an open range, severity not yet assigned.
    let pam = record("DEBIAN-CVE-2024-10041");
    let advisory = osv::advisory(&pam, &release("debian-12")).unwrap();
    assert_eq!(advisory.packages[0].fixed, None);
    assert_eq!(advisory.severity, "unrated");
    assert!(
        osv::advisory(&pam, &release("debian-13")).is_some(),
        "fixed in 13, still listed for it"
    );
    // Debian marks it unimportant: skipped, as debsecan does.
    let net_tools = record("DEBIAN-CVE-2002-1976");
    assert!(osv::advisory(&net_tools, &release("debian-12")).is_none());
}

#[test]
fn ubuntu_cve_records_count_and_notices_do_not() {
    let pcre2 = record("UBUNTU-CVE-2026-86145");
    let advisory = osv::advisory(&pcre2, &release("ubuntu-24.04")).unwrap();
    assert_eq!(advisory.advisory_id, "UBUNTU-CVE-2026-86145/ubuntu-24.04");
    assert_eq!(advisory.cves, ["CVE-2026-86145"]);
    assert_eq!(advisory.severity, "moderate", "Ubuntu priority medium");
    assert_eq!(advisory.packages[0].name, "pcre2");
    assert_eq!(advisory.packages[0].fixed, None);
    // USN notices repeat the per-CVE records; Pro ecosystems are skipped.
    let usn = record("USN-8820-1");
    assert!(osv::advisory(&usn, &release("ubuntu-22.04")).is_none());
}

#[test]
fn events_become_ranges() {
    let json = br#"{"id":"DEBIAN-CVE-2026-1000","affected":[{"package":{"name":"foo","ecosystem":"Debian:12"},
        "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"1.5"},
        {"introduced":"2.0"},{"last_affected":"2.3"}]},{"type":"GIT","events":[{"introduced":"abc"}]}]}]}"#;
    let advisory = osv::advisory(&osv::parse(json).unwrap(), &release("debian-12")).unwrap();
    let ranges: Vec<(Option<&str>, Option<&str>, Option<&str>)> = advisory
        .packages
        .iter()
        .map(|p| {
            (
                p.introduced.as_deref(),
                p.fixed.as_deref(),
                p.last_affected.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        ranges,
        [
            (Some("1.0"), Some("1.5"), None),
            (Some("2.0"), None, Some("2.3"))
        ],
        "GIT ranges ignored"
    );
}

#[test]
fn releases_map_from_os_release_and_ecosystems() {
    // Whole ecosystems: OSV's per-release files stopped in October 2024.
    assert_eq!(release("ubuntu-24.04").ecosystem(), "Ubuntu");
    assert_eq!(release("debian-12").ecosystem(), "Debian");
    assert_eq!(release("rocky-9").ecosystem(), "Rocky Linux");
    assert!(
        "fedora-44".parse::<Release>().is_err(),
        "Fedora has its own feed"
    );
    assert!(
        "rocky-9.4".parse::<Release>().is_err(),
        "major versions only"
    );
    assert!(osv::parse(b"{}").is_err());
    assert!(osv::parse(b"<html>").is_err());
}
