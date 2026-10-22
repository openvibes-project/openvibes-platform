//! The install form: where a run starts (#87) and what the form shows.

use platform_host::{Step, Unit};

use super::{
    app::{Key, Tab},
    nav::Screen,
    script_host::*,
    setup::Phase,
};

const NO_CA: &str = "# no ca\n";

/// A home whose default root key name is taken: the free name is `-2`.
fn taken_home(name: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!("ov-87-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("openvibes-root-ca.key"), "x").unwrap();
    home
}

/// #87, ruling 6: a plan from a first install that stopped before its CA
/// opens the install form, filled, with a free root key name; Start
/// installs (never a Repair, which refuses to make a CA).
#[test]
fn a_plan_without_a_ca_opens_the_install_form_filled() {
    let plan = format!("{PLAN}{NO_CA}").replace("platform.example.com", "planned.example.com");
    let mut app = app_with_plan(&plan, vec![]);
    assert_eq!(
        (app.nav.screen.clone(), app.tab),
        (Screen::Legacy, Tab::Setup)
    );
    assert_eq!(app.setup.phase, Phase::Form);
    let text = screen(&app);
    assert!(text.contains("Hostname:  planned.example.com"), "{text}");
    assert!(text.contains("Root key file:"), "{text}");
    assert!(text.contains("Esc back  q quit"), "{text}");
    start(&mut app, "pw");
    app.setup_tick();
    let calls = app.host.calls.borrow();
    assert!(calls[0].0.starts_with("setup-plan "), "{}", calls[0].0);
    assert_eq!(calls[1].0, format!("setup-step {}", Step::ALL[0].name()));
}

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

/// The #87 form keeps the plan's own choices: parts, a moved console port
/// (said why), and a careful CA.
#[test]
fn the_87_form_keeps_the_plans_parts_ports_and_ca() {
    let plan = format!("{PLAN}{NO_CA}")
        .replace("\"vulns\", \"rules\", ", "")
        .replace("console_port = 443", "console_port = 8443")
        .replace("ca = \"quick\"", "ca = \"careful\"");
    let mut app = app_with_plan(&plan, vec![]);
    app.host.taken = vec![443];
    app.fill_from_plan();
    let text = screen(&app);
    assert!(
        text.contains("Console port:  8443  (443 is in use)"),
        "{text}"
    );
    assert!(text.contains("CA:  careful"), "{text}");
    assert!(
        text.contains("[ ] vulns") && text.contains("[ ] rules"),
        "{text}"
    );
    assert!(text.contains("[x] agent"), "{text}");
}

#[test]
fn a_plan_that_does_not_parse_says_so_on_the_form() {
    let mut app = app_with_plan(&format!("components = 3\n{NO_CA}"), vec![]);
    assert_eq!(
        (app.nav.screen.clone(), app.setup.phase),
        (Screen::Legacy, Phase::Form)
    );
    let error = app.message.clone().expect("the parse error");
    let first = error.lines().next().unwrap().to_owned();
    assert!(
        screen(&app).contains(&first[..first.len().min(40)]),
        "{error}"
    );
    app.key(Key::Char('q'));
    assert!(app.quit);
}

#[test]
fn a_set_up_host_with_a_ca_starts_on_home() {
    let app = app_with_plan(PLAN, vec![]);
    assert_eq!(app.nav.screen, Screen::Home);
}

/// A run stopped at its first step, on a host whose plan is `plan`.
fn stopped(plan: &str) -> super::app::App<SetupHost> {
    let mut app = app_with_plan(
        plan,
        vec![Ok("written\n".into()), Ok("failed\tdnf\n".into())],
    );
    assert_eq!(app.nav.screen, Screen::Legacy, "starts on the form");
    start(&mut app, "pw");
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Stopped(0));
    app
}

#[test]
fn esc_after_a_stop_before_the_ca_returns_to_the_filled_form() {
    let mut app = stopped(&format!("{PLAN}{NO_CA}"));
    // The failed run's CA step wrote the default key after the TUI started.
    let home = taken_home("esc");
    app.setup.home = Some(home.display().to_string());
    app.setup.hostname = "typed.example.com".into();
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Legacy);
    assert_eq!(app.setup.phase, Phase::Form);
    assert_eq!(app.setup.hostname, "platform.example.com", "from the plan");
    assert_eq!(
        app.setup.root_key_out,
        home.join("openvibes-root-ca-2.key").display().to_string(),
        "the name taken since startup is skipped"
    );
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn esc_after_a_stop_after_the_ca_goes_home() {
    let mut app = stopped(&format!("{PLAN}{NO_CA}"));
    app.host.plan = PLAN.into(); // the CA step ran before the stop
    app.key(Key::Esc);
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

/// Reviewer on #115, the user's own moment: the console still set to 443,
/// nginx holding 443, our console not running; the #87 form says so.
#[test]
fn a_default_port_held_while_our_unit_is_down_is_named() {
    let status = |active: &str| platform_host::ServiceStatus {
        unit: Unit::Console,
        installed: true,
        enabled: true,
        active: active.into(),
        ready: None,
        since: None,
    };
    for (active, noted) in [("activating", true), ("failed", true), ("active", false)] {
        let mut app = app_with_plan(&format!("{PLAN}# no ca\n"), vec![]);
        app.host.taken = vec![443];
        app.services = vec![status(active)];
        app.fill_from_plan();
        let text = screen(&app);
        assert_eq!(
            text.contains("Console port:  443  (443 is in use by another program)"),
            noted,
            "{active}:\n{text}"
        );
    }
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
