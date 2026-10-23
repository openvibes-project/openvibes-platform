//! Choose what to install (advanced.py, full_advanced.py): the steps line,
//! Optional, Names, Ports, Review, and where Esc goes. The Certificates
//! step is in `certs_tests.rs`.

use platform_host::{HostError, StepState};

use super::{Ca, Stage};
use crate::{
    setup::request::RequestState,
    tui::{
        app::{App, Key},
        nav::Screen,
        script_host::{PLAN, SetupHost, app_taken, app_with_plan, fresh_app, screen, type_text},
    },
};

/// `app` at step `step` (0..=4) of Choose what to install, its first row.
pub(super) fn at(mut app: App<SetupHost>, step: u8) -> App<SetupHost> {
    app.install.hostname = "limebox.lan".into();
    app.install.home = Some("/home/u".into());
    app.nav.screen = Screen::Install(Stage::Step(step));
    app.nav.row = 0;
    app
}

/// A fresh host at step `step`.
pub(super) fn steps(step: u8) -> App<SetupHost> {
    at(fresh_app(), step)
}

pub(super) fn down(app: &mut App<SetupHost>, n: usize) {
    for _ in 0..n {
        app.key(Key::Down);
    }
}

pub(super) fn calls(app: &App<SetupHost>) -> Vec<String> {
    app.host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect()
}

pub(super) fn answer(app: &App<SetupHost>, answer: Result<String, HostError>) {
    app.host.answers.borrow_mut().push_back(answer);
}

/// A folder that exists, for the root key; removed when dropped, so keep
/// it bound while the test uses it.
pub(super) struct Folder(String);

impl std::fmt::Display for Folder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(super) fn folder(name: &str) -> Folder {
    let dir = std::env::temp_dir().join(format!("ov-steps-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Folder(dir.display().to_string())
}

#[test]
fn steps_line_marks_done_current_to_come() {
    let text = screen(&steps(2));
    assert!(text.contains("· Install › Certificates"), "{text}");
    assert!(
        text.contains("✓ Optional  ✓ Names  ● Certificates  ○ Ports  ○ Review"),
        "{text}"
    );
    let text = screen(&steps(0));
    assert!(text.contains("· Install › Optional"), "{text}");
    assert!(
        text.contains("● Optional  ○ Names  ○ Certificates  ○ Ports  ○ Review"),
        "{text}"
    );
}

#[test]
fn optional_has_agent_on_and_assistant_off_and_next() {
    let mut app = steps(0);
    let text = screen(&app);
    for row in [
        "[x] Agent on this host",
        "watch this host too",
        "[ ] Assistant",
        "local AI helper · 2.7 GB download",
        "Next",
        "names",
        "Untick only if this server must not run an agent.",
        "Space  Select/deselect",
    ] {
        assert!(text.contains(row), "{row}\n{text}");
    }
    app.key(Key::Down);
    let text = screen(&app);
    assert!(
        text.contains("Answers questions about your findings, on this host, no cloud. Needs 4 GB."),
        "{text}"
    );
    // The model's licence, from the pin (the old model question showed it).
    let url = crate::model_fetch::pin_or_embedded().unwrap().license_url;
    let (head, tail) = url.split_at(url.rfind("/resolve/").unwrap() + "/resolve/".len());
    assert!(text.contains(&format!("    Licence: {head}  ")), "{text}");
    assert!(text.contains(&format!("    {tail}  ")), "{text}");
    app.key(Key::Char(' '));
    assert!(app.install.assistant);
    assert!(screen(&app).contains("[x] Assistant"));
    app.key(Key::Down);
    let text = screen(&app);
    assert!(
        text.contains("Go on to the names this host is reached by."),
        "{text}"
    );
    assert!(text.contains("Enter  Next"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(1)));
}

#[test]
fn names_edits_in_place_and_flags_a_bad_name() {
    let mut app = steps(1);
    let text = screen(&app);
    for row in ["Host name", "limebox.lan", "Other names", "certificates"] {
        assert!(text.contains(row), "{row}\n{text}");
    }
    assert!(
        text.contains("The name agents and your browser use to reach this host."),
        "{text}"
    );
    assert!(text.contains("Enter  Change"), "{text}");
    app.key(Key::Down);
    app.key(Key::Enter);
    type_text(&mut app, "192.168.1.10");
    let text = screen(&app);
    assert!(text.contains("192.168.1.10█"), "{text}");
    assert!(text.contains("Other names:"), "{text}");
    assert!(text.contains("Esc  Cancel"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.install.sans, "192.168.1.10");
    app.key(Key::Up);
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    type_text(&mut app, "not a name");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("✗ Host name: Not a DNS name"), "{text}");
    // Next is refused while a name is flagged.
    down(&mut app, 2);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(1)));
}

#[test]
fn ports_flags_taken_and_proposes() {
    let mut app = at(app_taken(false, vec![], vec![443]), 3);
    assert_eq!(app.install.console_port, "8443");
    let text = screen(&app);
    for row in [
        "· Install › Ports",
        "443 is in use by another process · 8443 proposed",
        "Agent connections",
        "18423",
        "Rule distribution",
        "18424",
        "Network devices",
        "514/udp · open it in your firewall",
        "Enter to keep 8443 or type another port.",
        "Enter  Change",
    ] {
        assert!(text.contains(row), "{row}\n{text}");
    }
    // Enter keeps the proposal: nothing is flagged any more.
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(!text.contains("proposed"), "{text}");
    assert!(text.contains("8443"), "{text}");
    assert_eq!(app.install.console_port, "8443");
    down(&mut app, 4);
    let text = screen(&app);
    assert!(text.contains("Go on to the review."), "{text}");
    assert!(text.contains("Enter  Next"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(4)));
}

#[test]
fn ports_accept_typed_port() {
    let mut app = steps(3);
    app.key(Key::Enter);
    assert!(screen(&app).contains("443█"));
    app.key(Key::ClearLine);
    type_text(&mut app, "18423");
    let text = screen(&app);
    assert!(
        text.contains("18423 is already used here for Agent connections."),
        "{text}"
    );
    // A refused port is not taken: Enter leaves it being typed.
    app.key(Key::Enter);
    assert!(app.install.editing.is_some());
    app.key(Key::ClearLine);
    type_text(&mut app, "8080");
    assert!(screen(&app).contains("8080 is free on this host."));
    app.key(Key::Enter);
    assert_eq!(app.install.console_port, "8080");
    assert!(app.install.editing.is_none());
    // Network devices is said, not edited.
    down(&mut app, 3);
    app.key(Key::Enter);
    assert!(app.install.editing.is_none());
}

#[test]
fn review_lists_every_choice_enter_jumps_to_step() {
    let mut app = steps(4);
    app.install.sans = "192.168.1.10".into();
    app.install.ca = Ca::OpenVibes;
    app.install.root_key_out = "/home/u/openvibes-root-ca.key".into();
    app.install.console_port = "8443".into();
    let text = screen(&app);
    for row in [
        "· Install › Review",
        "agent on this host · no assistant",
        "limebox.lan, 192.168.1.10",
        "OpenVIBES makes one · ~/openvibes-root-ca.key",
        "8443, 18423, 18424, 514/udp",
        "asks for your password once",
    ] {
        assert!(text.contains(row), "{row}\n{text}");
    }
    app.install.ca = Ca::Own;
    app.install.request = Some(RequestState::Signed {
        csr: String::new(),
        issuer: "Lime Lab Root CA".into(),
    });
    app.install.signed = Some("Lime Lab Root CA".into());
    let text = screen(&app);
    assert!(
        text.contains("your own CA · ✓ signed by Lime Lab Root CA"),
        "{text}"
    );
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(0)));
    let mut app = steps(4);
    down(&mut app, 2);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(2)));
    // Your own CA before both certificates are added: Install says why.
    let mut app = steps(4);
    down(&mut app, 4);
    let text = screen(&app);
    assert!(
        text.contains("✗ Certificates: add both certificates first."),
        "{text}"
    );
}

#[test]
fn review_install_asks_password_in_bar_once() {
    // Your own CA without both certificates added: Install is refused.
    let mut app = steps(4);
    down(&mut app, 4);
    app.key(Key::Enter);
    assert!(app.asking.is_none());
    assert!(calls(&app).is_empty());
    let mut app = steps(4);
    app.install.ca = Ca::OpenVibes;
    let dir = folder("review");
    app.install.root_key_out = format!("{dir}/openvibes-root-ca.key");
    down(&mut app, 4);
    let text = screen(&app);
    assert!(
        text.contains("Starts the install; it asks for your password once."),
        "{text}"
    );
    assert!(text.contains("Enter  Install"), "{text}");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Your password (sudo):"), "{text}");
    assert!(text.contains("Enter  Install"), "{text}");
    // Asked over Review (full_advanced.py 12); Esc on it stays there.
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(4)));
    assert!(text.contains("· Install › Review"), "{text}");
    app.key(Key::Esc);
    assert!(app.asking.is_none());
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(4)));
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls = calls(&app);
    assert!(calls[0].starts_with("setup-plan "), "{calls:?}");
    assert!(calls[0].contains("--ca quick"), "{calls:?}");
    assert!(app.host.calls.borrow().iter().all(|c| c.1 == "pw"));
    assert!(app.asking.is_none());
    assert_eq!(app.nav.screen, Screen::Install(Stage::Finished));
}

#[test]
fn esc_walks_back_a_step() {
    let mut app = steps(4);
    for step in [3, 2, 1, 0] {
        app.key(Key::Esc);
        assert_eq!(app.nav.screen, Screen::Install(Stage::Step(step)));
    }
}

#[test]
fn esc_on_step_one_goes_welcome_or_home() {
    let mut app = steps(0);
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Welcome));
    let mut app = app_with_plan(&format!("{PLAN}# no ca\n"), vec![]);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(0)));
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Home);
}

#[test]
fn issue_87_opens_step_one_filled_from_plan() {
    let plan = format!("{PLAN}# no ca\n")
        .replace("platform.example.com", "planned.example.com")
        .replace("sans = []", "sans = [\"10.0.0.5\"]")
        .replace("\"agent\"]", "\"agent\", \"assistant\"]")
        .replace("ca = \"quick\"", "ca = \"careful\"")
        .replace("console_port = 443", "console_port = 8443");
    let app = app_with_plan(&plan, vec![]);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(0)));
    let install = &app.install;
    assert_eq!(install.hostname, "planned.example.com");
    assert_eq!(install.sans, "10.0.0.5");
    assert_eq!(install.ca, Ca::Own);
    assert!(install.agent && install.assistant);
    assert_eq!(install.console_port, "8443");
    assert_eq!(
        install.root_key_out,
        super::fields::default_root_key(install.home.as_deref())
    );
    let text = screen(&app);
    assert!(text.contains("[x] Assistant"), "{text}");
}

/// #87: a plan that does not read keeps the defaults and says why on
/// step 1; a port it chose that another program holds now is moved and
/// said, unless the platform's own service holds it (#115).
#[test]
fn issue_87_says_a_bad_plan_and_moves_a_taken_port() {
    let app = app_with_plan("components = 3\n# no ca\n", vec![]);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(0)));
    let error = app.install.error.clone().expect("the parse error");
    let first: String = error.chars().take(30).collect();
    assert!(screen(&app).contains(&first), "{error}");
    let status = |active: &str| platform_host::ServiceStatus {
        unit: platform_host::Unit::Console,
        installed: true,
        enabled: true,
        active: active.into(),
        ready: None,
        since: None,
    };
    for (active, moved) in [("failed", true), ("active", false)] {
        let mut app = app_with_plan(&format!("{PLAN}# no ca\n"), vec![]);
        app.host.taken = vec![443];
        app.services = vec![status(active)];
        app.open_steps_from_plan();
        assert_eq!(app.install.proposed[0].is_some(), moved, "{active}");
        let console = if moved { "8443" } else { "443" };
        assert_eq!(app.install.console_port, console, "{active}");
    }
}

#[test]
fn esc_after_a_failed_install_goes_back_where_it_began() {
    let stop = || vec![Ok("written\n".into()), Ok("failed\tdnf\n".into())];
    // From Quick install: back to Quick install.
    let mut app = fresh_app();
    app.install.hostname = "limebox.lan".into();
    let dir = folder("quick");
    app.install.root_key_out = format!("{dir}/openvibes-root-ca.key");
    for a in stop() {
        answer(&app, a);
    }
    app.nav.screen = Screen::Install(Stage::Quick);
    down(&mut app, 4);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Running));
    assert!(matches!(
        app.run.as_ref().unwrap().states[1],
        Some(StepState::Failed(_))
    ));
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Quick));
    // From the steps: back to Review.
    let mut app = steps(4);
    app.install.ca = Ca::OpenVibes;
    let dir = folder("steps");
    app.install.root_key_out = format!("{dir}/openvibes-root-ca.key");
    for a in stop() {
        answer(&app, a);
    }
    down(&mut app, 4);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(4)));
}
