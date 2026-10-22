//! Welcome and Quick install (install.py `welcome`, quick.py): the
//! screens, the checks on the three typed fields, and the plan Install
//! starts.

use super::{Install, Stage};
use crate::tui::{
    app::{App, Key},
    nav::Screen,
    script_host::{SetupHost, app_taken, fresh_app, screen, type_text},
};

fn quick_from(mut app: App<SetupHost>) -> App<SetupHost> {
    app.install.hostname = "limebox.lan".into();
    // A new file in a folder that exists; nothing writes it.
    let tmp = std::env::temp_dir();
    let pid = std::process::id();
    app.install.root_key_out = format!("{}/ov-quick-{pid}-root-ca.key", tmp.display());
    app.nav.screen = Screen::Install(Stage::Quick);
    app
}

fn quick() -> App<SetupHost> {
    quick_from(fresh_app())
}

fn down(app: &mut App<SetupHost>, n: usize) {
    for _ in 0..n {
        app.key(Key::Down);
    }
}

fn calls(app: &App<SetupHost>) -> Vec<String> {
    app.host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect()
}

#[test]
fn fresh_host_opens_welcome_on_choose_what_to_install() {
    let app = fresh_app();
    assert_eq!(app.nav.screen, Screen::Install(Stage::Welcome));
    let text = screen(&app);
    assert!(text.contains("· Install"), "{text}");
    assert!(
        text.contains("This host does not run OpenVIBES yet."),
        "{text}"
    );
    assert!(text.contains("▸ Choose what to install"), "{text}");
    assert!(text.contains("components, names, ports"), "{text}");
    assert!(
        text.contains("everything, with default names and ports"),
        "{text}"
    );
    assert!(text.contains("Quit"), "{text}");
    assert!(text.contains("Enter  Open"), "{text}");
}

#[test]
fn welcome_enter_opens_the_steps_and_quick_install() {
    let mut app = fresh_app();
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(0)));
    let mut app = fresh_app();
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Quick));
}

#[test]
fn welcome_quit_and_q_quit() {
    let mut app = fresh_app();
    app.key(Key::Char('q'));
    assert!(app.quit);
    let mut app = fresh_app();
    down(&mut app, 2);
    app.key(Key::Enter);
    assert!(app.quit);
}

#[test]
fn quick_install_rows_and_help() {
    let mut app = quick();
    let text = screen(&app);
    assert!(text.contains("Install › Quick install"), "{text}");
    assert!(
        text.contains("Quick install: only what OpenVIBES cannot know"),
        "{text}"
    );
    for row in [
        "Host name",
        "Other names",
        "Root key file",
        "[x] Agent on this host",
        "watch this host too",
        "Install",
        "everything else uses the defaults",
    ] {
        assert!(text.contains(row), "{row}\n{text}");
    }
    assert!(
        text.contains("The name agents and your browser use to reach this host."),
        "{text}"
    );
    for (n, help) in [
        (
            1,
            "Other names or addresses agents may use, comma-separated.",
        ),
        (2, "The CA's root key: written once here, move it offline."),
        (3, "Untick only if this server must not run an agent."),
        (4, "Starts the install; it asks for your password once."),
    ] {
        app.key(Key::Down);
        let text = screen(&app);
        assert!(text.contains(help), "row {n}\n{text}");
    }
    assert!(screen(&app).contains("Enter  Install"));
}

#[test]
fn quick_agent_row_space_unticks() {
    let mut app = quick();
    down(&mut app, 3);
    let text = screen(&app);
    assert!(text.contains("Space"), "{text}");
    assert!(text.contains("Select/deselect"), "{text}");
    app.key(Key::Char(' '));
    assert!(!app.install.agent);
    assert!(screen(&app).contains("[ ] Agent on this host"));
    app.key(Key::Char(' '));
    assert!(app.install.agent);
}

#[test]
fn quick_edits_in_place() {
    let mut app = quick();
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Host name"), "{text}");
    assert!(text.contains("limebox.lan█"), "{text}");
    assert!(text.contains("Esc"), "{text}");
    // q is text while typing.
    for _ in 0..3 {
        app.key(Key::Backspace);
    }
    type_text(&mut app, "q.example");
    app.key(Key::Enter);
    assert_eq!(app.install.hostname, "limebox.q.example");
    // Esc cancels an edit.
    app.key(Key::Enter);
    type_text(&mut app, "x");
    app.key(Key::Esc);
    assert_eq!(app.install.hostname, "limebox.q.example");
    assert_eq!(app.nav.screen, Screen::Install(Stage::Quick));
    down(&mut app, 1);
    app.key(Key::Enter);
    type_text(&mut app, "192.168.1.10");
    app.key(Key::Enter);
    assert_eq!(app.install.sans, "192.168.1.10");
}

#[test]
fn quick_root_key_existing_relative_missing_folder_flagged() {
    let dir = super::steps_tests::folder("qf");
    let existing = format!("{dir}/exists.key");
    std::fs::write(&existing, "").unwrap();
    let dangling = format!("{dir}/dangling.key");
    let _ = std::fs::remove_file(&dangling);
    std::os::unix::fs::symlink("/no/such/target", &dangling).unwrap();
    let in_a_file = format!("{existing}/ca.key");
    let not_a_folder = format!("{existing} is not a folder.");
    for (path, said) in [
        (
            existing.as_str(),
            "That file already exists: choose another name.",
        ),
        (
            dangling.as_str(),
            "That file already exists: choose another name.",
        ),
        (in_a_file.as_str(), not_a_folder.as_str()),
        ("openvibes.key", "The path must start with /."),
        (
            "/no/such/folder/ca.key",
            "The folder /no/such/folder does not exist.",
        ),
    ] {
        let mut app = quick();
        app.install.root_key_out = path.into();
        let text = screen(&app);
        assert!(text.contains(said), "{path}\n{text}");
        // Install is refused while a field is flagged.
        down(&mut app, 4);
        app.key(Key::Enter);
        assert!(calls(&app).is_empty());
        assert!(app.asking.is_none());
        assert_eq!(app.nav.screen, Screen::Install(Stage::Quick));
    }
}

#[test]
fn quick_flags_a_bad_host_name() {
    let mut app = quick();
    app.install.hostname = "Not A Name".into();
    let text = screen(&app);
    assert!(text.contains("✗ Host name: Not a DNS name"), "{text}");
    down(&mut app, 4);
    app.key(Key::Enter);
    assert!(app.asking.is_none());
}

#[test]
fn quick_install_starts_with_quick_ca_and_core_components() {
    let mut app = quick();
    app.install.sans = "192.168.1.10".into();
    let key = app.install.root_key_out.clone();
    down(&mut app, 4);
    app.key(Key::Enter);
    // The password is asked over Quick install.
    assert!(app.asking.is_some());
    assert_eq!(app.nav.screen, Screen::Install(Stage::Quick));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(
        calls(&app)[0],
        format!(
            "setup-plan --components ingest,console,distribution,vulns,rules,signer,agent \
             --hostname limebox.lan --san 192.168.1.10 --ca quick --root-key-out {key} \
             --console-port 443 --ingest-port 18423 --distribution-port 18424"
        )
    );
    assert_eq!(app.nav.screen, Screen::Install(Stage::Finished));
}

#[test]
fn quick_taken_port_moves_and_says_so() {
    let mut app = quick_from(app_taken(false, vec![], vec![443]));
    assert_eq!(app.install.console_port, "8443");
    down(&mut app, 4);
    let text = screen(&app);
    assert!(text.contains("443 is in use"), "{text}");
    assert!(text.contains("the console uses 8443"), "{text}");
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(calls(&app)[0].contains("--console-port 8443"));
}

#[test]
fn esc_on_quick_goes_to_welcome() {
    let mut app = quick();
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Welcome));
}

#[test]
fn install_defaults_keep_the_agent_on() {
    assert!(Install::new("h".into(), None).agent);
}

/// A paste outside the paste box presses no keys: q on Welcome does not
/// quit, its line end on Review's Install row starts nothing (as root, no
/// password asked first).
#[test]
fn a_stray_paste_presses_no_keys() {
    let mut app = fresh_app();
    app.key(Key::Paste("q\n".into()));
    assert!(!app.quit);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Welcome));
    let mut app = super::steps_tests::steps(4);
    app.host.root = true;
    app.nav.row = 4;
    app.key(Key::Paste("some text\n".into()));
    assert!(calls(&app).is_empty(), "{:?}", calls(&app));
    assert!(app.run.is_none() && app.asking.is_none());
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(4)));
}

/// A field being typed takes a paste's characters, never its line end.
#[test]
fn a_paste_into_a_field_types_it_without_the_line_end() {
    let mut app = quick();
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    app.key(Key::Paste("lime.lan\r\n".into()));
    assert!(app.install.editing.is_some(), "still typing");
    app.key(Key::Enter);
    assert_eq!(app.install.hostname, "lime.lan");
}
