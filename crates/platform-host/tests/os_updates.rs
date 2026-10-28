use platform_host::os_updates::{OsUpdates, check_update_packages, os_release, security_packages};

const CHECK: &str = "
kernel.x86_64                  5.14.0-570.12.1.el9_6     baseos
openssl-libs.x86_64            1:3.2.2-6.el9_5.1         baseos
vim-minimal.x86_64             2:8.2.2637-21.el9         baseos

Obsoleting Packages
foo.x86_64                     2.0-1.el9                 appstream
    foo-old.x86_64             1.0-1.el9                 @appstream
";

const SECURITY: &str = "
RLSA-2026:1234 Important/Sec. openssl-libs-1:3.2.2-6.el9_5.1.x86_64
RLSA-2026:1235 Moderate/Sec.  openssl-libs-1:3.2.2-6.el9_5.1.x86_64
RLSA-2026:1236 Important/Sec. kernel-5.14.0-570.12.1.el9_6.x86_64
RLSA-2026:1237 Low/Sec.       unrelated-1.0-1.el9.x86_64
";

#[test]
fn the_listing_stops_at_the_obsoletes() {
    assert_eq!(
        check_update_packages(CHECK),
        ["kernel", "openssl-libs", "vim-minimal"]
    );
}

#[test]
fn no_updates_is_an_empty_listing() {
    assert!(check_update_packages("").is_empty());
    assert!(check_update_packages("\n").is_empty());
}

#[test]
fn a_package_with_two_advisories_counts_once() {
    assert_eq!(
        security_packages(SECURITY),
        ["openssl-libs", "kernel", "unrelated"]
    );
}

#[test]
fn security_counts_only_packages_that_are_waiting() {
    let found = OsUpdates::from_listings(CHECK, SECURITY, true, 1_700_000_000);
    assert_eq!(found.total, 3);
    assert_eq!(found.security, 2);
    assert!(found.kernel);
    assert!(found.restart);
}

#[test]
fn garbage_is_not_a_package() {
    assert!(
        check_update_packages("Last metadata expiration check: 0:01:00 ago\nError: x\n").is_empty()
    );
}

#[test]
fn the_file_round_trips_and_ignores_unknown_keys() {
    let found = OsUpdates {
        total: 23,
        security: 4,
        kernel: true,
        restart: false,
        checked_at: 42,
    };
    assert_eq!(OsUpdates::from_file(&found.to_file()), Some(found));
    let more = format!("{}later=1\n", found.to_file());
    assert_eq!(OsUpdates::from_file(&more), Some(found));
}

#[test]
fn a_file_without_a_check_time_is_not_a_check() {
    assert_eq!(OsUpdates::from_file("total=3\n"), None);
    assert_eq!(OsUpdates::from_file("total=x\nchecked_at=1\n"), None);
}

#[test]
fn the_name_comes_from_os_release() {
    let text = "NAME=\"AlmaLinux\"\nPRETTY_NAME=\"AlmaLinux 9.6 (Sage Margay)\"\n";
    assert_eq!(
        os_release(text).as_deref(),
        Some("AlmaLinux 9.6 (Sage Margay)")
    );
    assert_eq!(os_release("NAME=x\n"), None);
}
