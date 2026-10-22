//! The install form (Task 5 deletes it): where #87 starts and what the form shows.
use super::{app::Key, nav::Screen, script_host::*, setup::Phase};

const NO_CA: &str = "# no ca\n";

/// A Remove everything that stopped after the CA went (purge) but before
/// `setup.toml` did: Home, whose Status shows the half-done uninstall,
/// not the install form.
#[test]
fn a_half_done_remove_everything_starts_on_home() {
    let mut app = app_with_plan(&format!("{PLAN}{NO_CA}"), vec![]);
    let run = app.root.join("run/openvibes-admin");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("job"), "uninstall\neverything").unwrap();
    app.files_changed();
    app.start_screen();
    assert_eq!(app.nav.screen, Screen::Home);
    let _ = std::fs::remove_dir_all(&app.root);
}

/// The CA's presence is read at start, on refresh and as a run ends, not
/// on every draw.
#[test]
fn drawing_reads_no_certificates() {
    let app = app_with_plan(&format!("{PLAN}{NO_CA}"), vec![]);
    let before = app.host.cert_reads.get();
    for _ in 0..3 {
        screen(&app);
    }
    assert_eq!(app.host.cert_reads.get(), before);
}

/// Ruling (fix 1): the #87 form is not a trap; Home's Maintenance ›
/// Uninstall still works from there. A fresh host's form has no Home.
#[test]
fn esc_on_the_87_form_goes_home_but_not_on_a_fresh_form() {
    let mut app = app_with_plan(&format!("{PLAN}{NO_CA}"), vec![]);
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Home);
    let mut fresh = super::script_host::app(false, vec![]);
    fresh.key(Key::Esc);
    assert_eq!(
        (fresh.nav.screen.clone(), fresh.setup.phase),
        (Screen::Legacy, Phase::Form)
    );
    assert!(!screen(&fresh).contains("Esc back"));
}

#[test]
fn a_set_up_host_with_a_ca_starts_on_home() {
    let app = app_with_plan(PLAN, vec![]);
    assert_eq!(app.nav.screen, Screen::Home);
}

#[test]
fn a_taken_console_port_is_replaced_by_a_free_one_and_said_so() {
    let mut app = app_taken(false, vec![], vec![443, 8443]);
    let text = screen(&app);
    assert!(
        text.contains("Console port:  8444  (443 is in use)"),
        "{text}"
    );
    assert!(text.contains("Start"), "the form fits 80×24:\n{text}");
    // The operator may type another port.
    while app.setup.row != super::setup::PORT_ROW {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    app.key(Key::Backspace);
    app.key(Key::Backspace);
    type_text(&mut app, "50");
    app.key(Key::Enter);
    let args = app.setup.plan_args().join(" ");
    assert!(args.contains("--console-port 8450"), "{args}");
}

#[test]
fn a_taken_ingest_port_moves_to_a_free_one_and_distribution_keeps_its_own() {
    let app = app_taken(false, vec![], vec![18423]);
    let text = screen(&app);
    assert!(
        text.contains("Agent ports (ingest, distribution):  18425, 18424  (18423 is in use)"),
        "{text}"
    );
    let args = app.setup.plan_args().join(" ");
    assert!(
        args.ends_with("--console-port 443 --ingest-port 18425 --distribution-port 18424"),
        "{args}"
    );
}

#[test]
fn a_free_443_is_the_console_port() {
    let app = app(false, vec![]);
    let text = screen(&app);
    assert!(text.contains("Console port:  443"), "{text}");
    assert!(
        text.contains("Agent ports (ingest, distribution):  18423, 18424"),
        "{text}"
    );
    assert!(!text.contains("is taken"), "{text}");
}

/// Each form row is its own cursor position: the rows after the components
/// start after the last one (the signer row once shared row 7 with the
/// hostname: both were highlighted, and space there ticked the signer).
#[test]
fn every_form_row_is_its_own_cursor_position() {
    use crate::setup::plan::Component;
    assert_eq!(super::setup::HOSTNAME_ROW, Component::ALL.len());
    let mut app = app(false, vec![]);
    while app.setup.row != super::setup::HOSTNAME_ROW {
        app.key(Key::Down);
    }
    let before = app.setup.components.clone();
    app.key(Key::Char(' '));
    assert_eq!(
        app.setup.components, before,
        "space on Hostname ticks nothing"
    );
}

/// The form says what the selected row means (walkthrough, 2026-10-08: the
/// CA and root key fields were unexplained), and always-installed
/// components do not look like boxes to untick.
#[test]
fn the_form_explains_the_selected_row() {
    let mut app = app(false, vec![]);
    let text = screen(&app);
    assert!(
        text.contains("[•] ingest") && text.contains("[•] console"),
        "{text}"
    );
    assert!(text.contains("always installed"), "{text}");
    for (row, want) in [
        (
            super::setup::CA_ROW,
            "made here; its key is written once to the file below",
        ),
        (
            super::setup::KEY_ROW,
            "the only copy of the root key; move it offline after Setup",
        ),
        (
            super::setup::START_ROW,
            "installs the ticked components; takes a few minutes",
        ),
    ] {
        while app.setup.row != row {
            app.key(Key::Down);
        }
        let text = screen(&app);
        assert!(
            text.contains(want),
            "row {row}: missing {want:?} in\n{text}"
        );
    }
}

#[test]
fn the_assistant_asks_before_downloading_its_model_and_n_skips_it() {
    let mut app = app(false, vec![Ok("setup.toml written\n".into())]);
    app.setup
        .components
        .insert(crate::setup::plan::Component::Assistant);
    while app.setup.row != super::setup::START_ROW {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    assert_eq!(app.setup.phase, Phase::Model);
    let text = screen(&app);
    assert!(
        text.contains("Download the assistant's model (2.7 GB from Hugging Face)?"),
        "{text}"
    );
    assert!(
        text.contains("Licence:") && text.contains("https://huggingface.co/"),
        "{text}"
    );
    assert!(!text.contains("sudo openvibes-admin assistant"), "{text}");
    app.key(Key::Char('n'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(app.host.calls.borrow()[0].0.contains("--model skip"));
}

#[test]
fn y_downloads_the_model_and_no_assistant_means_no_question() {
    let mut app = app(false, vec![Ok("setup.toml written\n".into())]);
    app.setup
        .components
        .insert(crate::setup::plan::Component::Assistant);
    while app.setup.row != super::setup::START_ROW {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(app.host.calls.borrow()[0].0.contains("--model fetch"));
    let mut plain = app_taken(false, vec![], vec![]);
    while plain.setup.row != super::setup::START_ROW {
        plain.key(Key::Down);
    }
    plain.key(Key::Enter);
    assert!(matches!(plain.setup.phase, Phase::Password(_)));
}
