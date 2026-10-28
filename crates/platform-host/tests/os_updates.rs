use platform_host::os_updates::{
    OsUpdates, check_update_packages, os_release, restart_answer, short_kernel,
};

const CHECK: &str = "
kernel.x86_64                  5.14.0-570.12.1.el9_6     baseos
openssl-libs.x86_64            1:3.2.2-6.el9_5.1         baseos
vim-minimal.x86_64             2:8.2.2637-21.el9         baseos

Obsoleting Packages
foo.x86_64                     2.0-1.el9                 appstream
    foo-old.x86_64             1.0-1.el9                 @appstream
";

/// dnf4 puts a name wider than its column on a line of its own.
const WRAPPED: &str = "
kernel.x86_64                  5.14.0-570.12.1.el9_6     baseos
texlive-collection-fontsrecommended.noarch
                               9:20200406-26.el9_2       appstream
vim-minimal.x86_64             2:8.2.2637-21.el9         baseos
";

/// What `dnf5 check-update --security` prints for one package.
const SECURITY: &str = "kernel.x86_64                  5.14.0-570.12.1.el9_6     baseos
";

#[test]
fn the_listing_stops_at_the_obsoletes() {
    assert_eq!(
        check_update_packages(CHECK),
        ["kernel", "openssl-libs", "vim-minimal"]
    );
}

#[test]
fn a_wrapped_name_is_joined_with_its_version_line() {
    assert_eq!(
        check_update_packages(WRAPPED),
        [
            "kernel",
            "texlive-collection-fontsrecommended",
            "vim-minimal"
        ]
    );
}

#[test]
fn no_updates_is_an_empty_listing() {
    assert!(check_update_packages("").is_empty());
    assert!(check_update_packages("\n").is_empty());
}

#[test]
fn garbage_is_not_a_package() {
    assert!(
        check_update_packages("Last metadata expiration check: 0:01:00 ago\nError: x\n").is_empty()
    );
}

#[test]
fn security_is_the_second_listing_in_the_same_format() {
    let found = OsUpdates::from_listings(CHECK, SECURITY, true, 1_700_000_000);
    assert_eq!((found.total, found.security), (3, 1));
    assert!(found.kernel && found.restart);
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
fn restart_is_decided_by_the_plugins_own_words() {
    assert_eq!(
        restart_answer(
            "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n"
        ),
        Some(true)
    );
    assert_eq!(
        restart_answer(
            "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n"
        ),
        Some(false)
    );
    // The plugin is missing, or dnf5 has no D-Bus: not an answer.
    assert_eq!(
        restart_answer("No such command: needs-restarting. Please use /usr/bin/dnf --help\n"),
        None
    );
    assert_eq!(restart_answer("Couldn't connect to D-Bus\n"), None);
    assert_eq!(restart_answer(""), None);
}

#[test]
fn the_kernel_loses_its_distribution_and_architecture() {
    assert_eq!(
        short_kernel("5.14.0-570.12.1.el9_6.x86_64\n"),
        "5.14.0-570.12.1"
    );
    assert_eq!(short_kernel("6.17.4-300.fc44.x86_64"), "6.17.4-300");
    assert_eq!(short_kernel("6.1.0-13-amd64"), "6.1.0-13-amd64");
    assert_eq!(short_kernel("5.14.0-570"), "5.14.0-570");
}

#[test]
fn the_name_comes_from_os_release_with_fallbacks() {
    let text = "NAME=\"AlmaLinux\"\nPRETTY_NAME=\"AlmaLinux 9.6 (Sage Margay)\"\n";
    assert_eq!(os_release(text), "AlmaLinux 9.6 (Sage Margay)");
    assert_eq!(
        os_release("NAME=\"Rocky Linux\"\nVERSION_ID=\"9.6\"\n"),
        "Rocky Linux 9.6"
    );
    assert_eq!(os_release("NAME=Arch\n"), "Arch");
    assert_eq!(os_release(""), "Linux");
}
