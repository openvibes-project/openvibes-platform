//! Maintenance › Ports and addresses, key by key (maint2.py #4-6,
//! maint2b.py #13-17).

use platform_host::Step;

use crate::{
    setup::plan::plan_of,
    tui::{
        app::{App, Key},
        maint::Page,
        script_host::{PLAN, SetupHost, app_taken, screen, type_text},
    },
};

/// The page on a host where 8080 belongs to another program.
fn page() -> App<SetupHost> {
    let mut app = app_taken(true, vec![], vec![8080, 18423]);
    app.host.plan = PLAN.into();
    app.open_page(Page::Ports);
    app
}

/// Enter on Agent connections, the typed port replaced by `port`.
fn type_agent_port(app: &mut App<SetupHost>, port: &str) {
    app.nav.row = 1;
    app.key(Key::Enter);
    for _ in 0..5 {
        app.key(Key::Backspace);
    }
    type_text(app, port);
}

#[test]
fn the_page_lists_every_port() {
    let mut app = page();
    let text = screen(&app);
    for want in [
        "Console",
        "443 · https://platform.example.com",
        "Agent connections",
        "18423",
        "Rule distribution",
        "18424",
        "Network devices",
        "514/udp",
        "The console's port; the web address follows it.",
        "Enter  Change",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("Apply"), "{text}");
    app.nav.row = 3;
    let text = screen(&app);
    assert!(!text.contains("Change"), "{text}");
    app.key(Key::Enter);
    assert!(!app.maint.editing());
}

#[test]
fn a_taken_port_is_said_at_once() {
    let mut app = page();
    type_agent_port(&mut app, "8080");
    let text = screen(&app);
    assert!(
        text.contains("✗ 8080 is used by another program on this host: choose another.")
            && text.contains("Agent connections: type a port"),
        "{text}"
    );
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("8080█") && !text.contains("* Agent"),
        "{text}"
    );
}

#[test]
fn a_free_port_is_said_free() {
    let mut app = page();
    type_agent_port(&mut app, "18500");
    assert!(screen(&app).contains("18500 is free on this host."));
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(!text.contains("https://"), "{text}");
    for want in ["* Agent connections", "18500 · was 18423", "Apply"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Down);
    let text = screen(&app);
    assert!(
        text.contains("agents must be told the new port")
            && text.contains("Agents on other hosts need their install line again after this."),
        "{text}"
    );
    // Esc keeps the old value.
    let mut app = page();
    type_agent_port(&mut app, "18500");
    app.key(Key::Esc);
    let text = screen(&app);
    assert!(text.contains("18423") && !text.contains("Apply"), "{text}");
}

#[test]
fn a_port_another_row_uses_is_refused() {
    let mut app = page();
    type_agent_port(&mut app, "18424");
    let text = screen(&app);
    assert!(
        text.contains("✗ 18424 is already used here for Rule distribution."),
        "{text}"
    );
}

#[test]
fn a_reserved_port_is_refused() {
    let mut app = page();
    type_agent_port(&mut app, "18430");
    assert!(screen(&app).contains("✗ 18430 is not allowed for Agent connections"));
}

#[test]
fn its_own_port_counts_as_free() {
    let mut app = page();
    type_agent_port(&mut app, "18423");
    assert!(screen(&app).contains("18423 is free on this host."));
    app.key(Key::Enter);
    assert!(!screen(&app).contains("Apply"));
}

#[test]
fn apply_moves_the_port() {
    let mut app = page();
    type_agent_port(&mut app, "18500");
    app.key(Key::Enter);
    app.nav.row = 4;
    app.key(Key::Enter);
    assert!(screen(&app).contains("Move agents to 18500?"));
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let mut plan = plan_of(PLAN).unwrap();
    plan.ingest_port = 18500;
    let calls: Vec<String> = app
        .host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect();
    assert_eq!(calls[0], format!("setup-plan {}", plan.args().join(" ")));
    assert!(calls[0].contains("--ingest-port 18500"));
    // Every step once, Ready before the model.
    let steps: Vec<&String> = calls
        .iter()
        .filter(|c| c.starts_with("setup-step"))
        .collect();
    assert_eq!(steps.len(), Step::ALL.len());
    assert_eq!(calls.last().unwrap(), "setup-status");
    let text = screen(&app);
    for want in [
        "Moving agent connections",
        "Save the ports",
        "Restart with the new port",
        "Open the new port",
        "Close the old port",
        "Ready",
        "Moved to 18500 · new install line: console › Enrollment (",
        "Enter  Back",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn the_console_question_and_result() {
    let mut app = page();
    app.nav.row = 0;
    app.key(Key::Enter);
    for _ in 0..3 {
        app.key(Key::Backspace);
    }
    type_text(&mut app, "8443");
    app.key(Key::Enter);
    assert!(!app.maint.editing());
    app.nav.row = 4;
    assert!(screen(&app).contains("https://platform.example.com:8443"));
    app.key(Key::Enter);
    assert!(screen(&app).contains("Move the console to 8443?"));
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(
        screen(&app).contains("Console moved to 8443 · https://platform.example.com:8443 ("),
        "{}",
        screen(&app)
    );
}

#[test]
fn a_port_below_1024_is_for_the_console_only() {
    let mut app = page();
    type_agent_port(&mut app, "80");
    assert!(screen(&app).contains("✗ Agent connections need a port from 1024 up."));
    app.key(Key::Esc);
    app.nav.row = 2;
    app.key(Key::Enter);
    for _ in 0..5 {
        app.key(Key::Backspace);
    }
    type_text(&mut app, "80");
    assert!(screen(&app).contains("✗ Rule distribution needs a port from 1024 up."));
    app.key(Key::Esc);
    app.nav.row = 0;
    app.key(Key::Enter);
    for _ in 0..3 {
        app.key(Key::Backspace);
    }
    type_text(&mut app, "80");
    assert!(screen(&app).contains("80 is free on this host."));
}

#[test]
fn refusals_name_the_row_and_a_swap_waits_for_apply() {
    let mut app = page();
    type_agent_port(&mut app, "18430");
    assert!(
        screen(&app).contains("✗ 18430 is not allowed for Agent connections"),
        "{}",
        screen(&app)
    );
    app.key(Key::Esc);
    type_agent_port(&mut app, "18500");
    app.key(Key::Enter);
    app.nav.row = 2;
    app.key(Key::Enter);
    for _ in 0..5 {
        app.key(Key::Backspace);
    }
    type_text(&mut app, "18423");
    assert!(
        screen(&app).contains("✗ 18423 is still used by Agent connections until Apply."),
        "{}",
        screen(&app)
    );
}

#[test]
fn the_page_and_check_ports_agree() {
    use crate::setup::ports::check_ports;
    // (typed in Agent connections, console, distribution)
    for typed in ["18430", "80", "18424", "0"] {
        let mut app = page();
        type_agent_port(&mut app, typed);
        let refused = check_ports(443, typed.parse().unwrap(), 18424).is_err();
        assert!(refused, "check_ports accepts {typed}");
        assert!(screen(&app).contains('✗'), "{typed}: {}", screen(&app));
    }
    let mut app = page();
    type_agent_port(&mut app, "18500");
    assert!(check_ports(443, 18500, 18424).is_ok() && !screen(&app).contains('✗'));
}
