//! Maintenance › Certificates as certs2.py and certs4a.py show it:
//! automatic renewal, the intermediate, the previous one while agents move
//! over. Split from `certs_tests.rs` (size).

use chrono::{Duration, Utc};

use super::certs_tests::{app_with, pems, plan_text};
use crate::tui::{
    app::{App, Key},
    maint::Page,
    nav::Screen,
    script_host::{SetupHost, body, screen},
};

/// `YYYY-MM-DD` of `days` from today.
pub(super) fn day(days: i64) -> String {
    (Utc::now() + Duration::days(days))
        .format("%Y-%m-%d")
        .to_string()
}

/// When the intermediate of `pems` ends.
pub(super) fn int_until(pems: &[(&str, String)]) -> String {
    let end = platform_pki::not_after(&pems[1].1).unwrap();
    end.format("%Y-%m-%d").to_string()
}

/// A screen's body as the mockups draw it (gen.py `screen`): the header,
/// `lines`, blank lines to the bar, and the bar's middle line `bar`, in
/// the TUI's own bar box (one column in from each side).
pub(super) fn framed(title: &str, lines: Vec<String>, bar: &str) -> String {
    let rule = "━".repeat(70 - title.chars().count());
    let mut all = vec![
        String::new(),
        format!("    ━━ {title} {rule}"),
        String::new(),
    ];
    all.extend(lines);
    all.resize(14, String::new());
    all.extend([
        format!(" ┌{}┐", "─".repeat(76)),
        format!(" │{bar:<76}│"),
        format!(" └{}┘", "─".repeat(76)),
    ]);
    all.join("\n")
}

/// The bar of a list: ⭡⭣ Move, Enter `enter`, Esc Back and ?.
pub(super) fn keys(enter: &str) -> String {
    format!("  ⭡⭣  Move   Enter  {enter:<40}Esc  Back    ?  ")
}

/// A list (gen.py `menu`): one blank line between entries.
pub(super) fn menu(rows: &[(&str, String)], row: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for (i, (name, value)) in rows.iter().enumerate() {
        let mark = if i == row { "  ▸ " } else { "    " };
        lines.extend([format!("{mark}{name:<26} {value}"), String::new()]);
    }
    lines.pop();
    lines
}

/// The page of certs2.py: `rows` (name, value), then the two actions.
pub(super) fn page_body(rows: &[(&str, String)], quick: bool, row: usize) -> String {
    let mut lines: Vec<String> = rows
        .iter()
        .map(|(n, v)| format!("    {n:<26} {v}"))
        .collect();
    let replace = if quick {
        "needs the offline root key file"
    } else {
        "a new request for your CA"
    };
    lines.push(String::new());
    lines.extend(menu(
        &[
            ("Names", "add or remove a name agents use".into()),
            ("Replace the intermediate", replace.into()),
        ],
        row,
    ));
    let enter = ["Names", "Replace the intermediate"][row];
    framed("Certificates", lines, &keys(enter))
}

#[test]
fn certificates_page_own_ca_matches_certs2() {
    let pems = pems(10);
    let until = int_until(&pems);
    let mut app = app_with(pems);
    app.host.plan = plan_text().replace("quick", "careful");
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    let rows = [
        (
            "Web and agents",
            format!("renewed automatically · next {}", day(50)),
        ),
        ("Names", "limebox.lan, 192.168.1.10".into()),
        (
            "Intermediate",
            format!("signed by OpenVIBES Root CA · until {until}"),
        ),
    ];
    assert_eq!(body(&app), page_body(&rows, false, 1));
}

/// The rows of certs2.py `OURS` for these certificates.
pub(super) fn ours(pems: &[(&str, String)], previous: Option<&str>) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        (
            "Web and agents",
            format!("renewed automatically · next {}", day(50)),
        ),
        ("Names", "limebox.lan, 192.168.1.10".into()),
        (
            "Intermediate",
            format!("signed by the OpenVIBES root · until {}", int_until(pems)),
        ),
    ];
    if let Some(until) = previous {
        rows.push((
            "Previous intermediate",
            format!("trusted until {until}, as agents move over"),
        ));
    }
    rows.push((
        "Root key",
        "offline: needed only to replace the intermediate".into(),
    ));
    rows
}

#[test]
fn certificates_page_ours_matches_certs2() {
    let pems = pems(10);
    let mut app = app_with(pems.clone());
    app.open_page(Page::Certificates);
    assert_eq!(body(&app), page_body(&ours(&pems, None), true, 0));
    app.key(Key::Down);
    assert_eq!(body(&app), page_body(&ours(&pems, None), true, 1));
}

/// Writes `text` at `path` under the app's root.
pub(super) fn put(app: &App<SetupHost>, path: &str, text: &str) {
    let path = app.root.join(path.trim_start_matches('/'));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn certificates_page_shows_the_previous_intermediate() {
    let pems = pems(10);
    let mut app = app_with(pems.clone());
    put(&app, "/etc/openvibes/pki/previous.crt", &pems[1].1);
    let until = Utc::now() + Duration::days(31);
    put(
        &app,
        "/etc/openvibes/pki/previous-until",
        &format!("{}\n", until.to_rfc3339()),
    );
    app.open_page(Page::Certificates);
    let date = until.format("%Y-%m-%d").to_string();
    assert_eq!(body(&app), page_body(&ours(&pems, Some(&date)), true, 0));
    // Ruling 7: no second replacement while agents move over.
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Certificates));
    let text = screen(&app)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let want = format!(
        "The previous intermediate is still trusted until {date}, while agents move over: \
         replace it again after that."
    );
    assert!(text.contains(&want), "{text}");
    assert!(app.host.calls.borrow().is_empty());
}

#[test]
fn renewal_due_today_and_failing_texts() {
    // 20 days left: past the renewal date, more than 14 left.
    let mut app = app_with(pems(70));
    app.open_page(Page::Certificates);
    assert!(screen(&app).contains("Web and agents             renewed automatically · due today"));
    // 10 days left: the timer has not managed it.
    let mut app = app_with(pems(80));
    app.open_page(Page::Certificates);
    assert!(screen(&app).contains("Web and agents             renewal is failing · see Status"));
    // A careful CA's root is not here: no Root key row.
    let mut app = app_with(pems(10));
    app.host.plan = plan_text().replace("quick", "careful");
    app.open_page(Page::Certificates);
    assert!(!screen(&app).contains("Root key"));
}
