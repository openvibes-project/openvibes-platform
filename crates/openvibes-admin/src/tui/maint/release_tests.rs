//! Update OpenVIBES on the appliance (#674; updates.py #7 to #11): the
//! release from update-check, the download and its check first.

use platform_host::HostError;

use super::release::{Release, newer, parse};
use crate::tui::{
    app::{App, Key},
    maint::Page,
    script_host::{SetupHost, screen, set_up},
};

/// The appliance's TUI, as root (no password), with these helper answers.
fn appliance(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = set_up(answers);
    app.host.appliance.set(true);
    app.host.root = true;
    app.packages = Some(Ok(Vec::new()));
    app
}

fn calls(app: &App<SetupHost>) -> Vec<String> {
    app.host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect()
}

const FOUND: &str = "done\t9.9.9\t2026-12-02\t312000000\toffline updates over SFTP · fixes";

#[test]
fn the_answer_and_the_versions() {
    assert_eq!(parse("none"), Some(None));
    assert_eq!(
        parse("9.9.9\t2026-12-02\t312000000\tfixes"),
        Some(Some(Release {
            version: "9.9.9".into(),
            published: "2026-12-02".into(),
            size: 312_000_000,
            new: "fixes".into(),
        }))
    );
    assert_eq!(parse("../x\t2026\t1\t"), None);
    assert!(newer("0.3.3", "0.3.2") && newer("0.10.0", "0.9.9"));
    assert!(!newer("0.3.2", "0.3.2") && !newer("0.3.1", "0.3.2"));
}

#[test]
fn opening_the_page_asks_github_and_shows_the_release() {
    let mut app = appliance(vec![Ok(FOUND.into())]);
    app.open_page(Page::Update);
    assert_eq!(calls(&app), ["update-check"]);
    let text = screen(&app);
    for want in [
        "9.9.9 available",
        "released 2026-12-02",
        "New: offline updates over SFTP · fixes",
        "Update now",
        "downloads 312 MB, checks its signature",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    // Check again is one row further down.
    for _ in 0..3 {
        app.key(Key::Down);
    }
    assert!(screen(&app).contains("Check again"), "{}", screen(&app));
}

#[test]
fn update_now_downloads_and_checks_before_the_six_steps() {
    let mut app = appliance(vec![Ok(FOUND.into())]);
    app.open_page(Page::Update);
    app.nav.row = 1;
    app.key(Key::Enter);
    assert!(
        screen(&app).contains("Update to 9.9.9?"),
        "{}",
        screen(&app)
    );
    app.key(Key::Enter);
    let calls = calls(&app);
    assert_eq!(calls[1], "update-fetch 9.9.9 --size 312000000");
    assert_eq!(calls[2], "update-use 9.9.9");
    assert!(calls[3].starts_with("update-step backup"), "{calls:?}");
    assert!(calls[8].starts_with("update-step ready"), "{calls:?}");
    assert_eq!(calls.len(), 9);
}

#[test]
fn a_bad_signature_stops_before_anything_changes() {
    let mut app = appliance(vec![
        Ok(FOUND.into()),
        Ok("done\t/var/lib/openvibes/updates/x.tar".into()),
        Err(HostError::Failed(
            "the update file is not signed by OpenVIBES' key: it is corrupted or altered, nothing changed"
                .into(),
        )),
    ]);
    app.open_page(Page::Update);
    app.nav.row = 1;
    app.key(Key::Enter);
    app.key(Key::Enter);
    assert_eq!(calls(&app).len(), 3, "no update step ran");
    let text = screen(&app);
    assert!(text.contains("Check its signature"), "{text}");
    assert!(text.contains("not signed by OpenVIBES' key"), "{text}");
    assert!(text.contains("Nothing was changed"), "{text}");
    assert!(text.contains("Enter  Try again"), "{text}");
}

#[test]
fn without_internet_it_says_so_and_check_again_asks_once_more() {
    let mut app = appliance(vec![
        Err(HostError::Failed(
            "GitHub cannot be reached: Could not resolve host".into(),
        )),
        Ok(FOUND.into()),
    ]);
    app.open_page(Page::Update);
    let text = screen(&app);
    assert!(text.contains("GitHub cannot be reached"), "{text}");
    assert!(
        text.contains("Appliance settings › Network shows it"),
        "{text}"
    );
    assert!(!text.contains("Update now"), "{text}");
    // Check again is the last row.
    for _ in 0..5 {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    assert_eq!(calls(&app), ["update-check", "update-check"]);
    assert!(screen(&app).contains("9.9.9 available"));
}
