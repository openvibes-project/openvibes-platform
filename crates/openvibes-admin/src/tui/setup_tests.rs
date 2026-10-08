//! The Setup tab against a scripted host.

use std::{cell::RefCell, collections::VecDeque};

use platform_host::{
    Host, HostError, PackageUpdate, Privileged, Secret, Service, ServiceAction, ServiceStatus,
    Step, Unit,
};
use ratatui::{Terminal, backend::TestBackend};

use super::{
    app::{App, Key, Tab},
    render,
    setup::Phase,
};

pub(super) struct SetupHost {
    set_up: bool,
    /// What each privileged call returns, in order.
    answers: RefCell<VecDeque<Result<String, HostError>>>,
    /// (verb, password) of each call.
    calls: RefCell<Vec<(String, String)>>,
    /// `setup.toml`'s text; empty: not set up.
    plan: String,
    packages: Vec<PackageUpdate>,
    /// Ports another process listens on.
    taken: Vec<u16>,
    /// Running as root: sudo needs no password.
    root: bool,
}

impl Host for SetupHost {
    fn services(&self) -> Result<Vec<ServiceStatus>, HostError> {
        Ok(Vec::new())
    }
    fn service_action(&self, _: Unit, _: ServiceAction) -> Result<(), HostError> {
        Ok(())
    }
    fn logs(&self, _: Unit, _: u16) -> Result<Vec<String>, HostError> {
        Ok(Vec::new())
    }
    fn read_config(&self, _: Service) -> Result<String, HostError> {
        Err(HostError::NotOperator)
    }
    fn write_config(&self, _: Service, _: &str) -> Result<(), HostError> {
        Err(HostError::NotOperator)
    }
    fn is_set_up(&self) -> bool {
        self.set_up
    }
    fn needs_password(&self) -> bool {
        !self.root
    }
    fn certificates(&self) -> Vec<(&'static str, Result<String, HostError>)> {
        // A set-up host has its CA; a plan left by a first install that
        // stopped before the CA step does not (#87).
        if self.plan.is_empty() || self.plan.contains("# no ca") {
            Vec::new()
        } else {
            vec![("/etc/openvibes/pki/intermediate.crt", Ok(String::new()))]
        }
    }
    fn packages(&self) -> Result<Vec<PackageUpdate>, HostError> {
        Ok(self.packages.clone())
    }
    fn listeners(&self, port: u16) -> Result<String, HostError> {
        Ok(if self.taken.contains(&port) {
            format!("LISTEN 0 511 *:{port} *:*\n")
        } else {
            String::new()
        })
    }
    fn setup_plan(&self) -> Result<String, HostError> {
        if self.plan.is_empty() {
            Err(HostError::Failed("not set up".into()))
        } else {
            Ok(self.plan.clone())
        }
    }
    fn privileged(&self, verb: Privileged<'_>, password: &Secret) -> Result<String, HostError> {
        self.calls
            .borrow_mut()
            .push((verb.args().join(" "), password.expose().to_owned()));
        self.answers
            .borrow_mut()
            .pop_front()
            .unwrap_or(Ok("done\tok\n".into()))
    }
}

fn app(set_up: bool, answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    app_taken(set_up, answers, vec![])
}

fn app_taken(
    set_up: bool,
    answers: Vec<Result<String, HostError>>,
    taken: Vec<u16>,
) -> App<SetupHost> {
    let mut app = App::new(SetupHost {
        set_up,
        answers: RefCell::new(answers.into()),
        calls: RefCell::new(Vec::new()),
        plan: String::new(),
        packages: Vec::new(),
        taken,
        root: false,
    });
    app.setup.hostname = "platform.example.com".into();
    app.setup.root_key_out = "/home/alice/openvibes-root-ca.key".into();
    app
}

pub(super) fn screen(app: &App<SetupHost>) -> String {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| render(frame, app)).unwrap();
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                + "\n"
        })
        .collect()
}

pub(super) fn type_text(app: &mut App<SetupHost>, text: &str) {
    for c in text.chars() {
        app.key(Key::Char(c));
    }
}

/// From the form: Start, then the password.
fn start(app: &mut App<SetupHost>, password: &str) {
    while app.setup.row != super::setup::START_ROW {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    type_text(app, password);
    app.key(Key::Enter);
}

#[test]
fn a_new_host_opens_on_setup_with_the_components() {
    let app = app(false, vec![]);
    assert_eq!(app.tab, Tab::Setup);
    let text = screen(&app);
    for want in [
        "[Setup]",
        "[•] ingest",
        "[x] agent",
        "[ ] assistant",
        "platform.example.com",
        "Start",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn a_set_up_host_opens_on_services() {
    assert_eq!(app(true, vec![]).tab, Tab::Services);
}

#[test]
fn start_writes_the_plan_with_the_password_then_runs_one_step_per_tick() {
    let mut app = app(
        false,
        vec![
            Ok("setup.toml written\n".into()),
            Ok("done\tinstalled\n".into()),
            Ok("failed\tdnf: no network\n".into()),
        ],
    );
    start(&mut app, "pw pw pw");
    {
        let calls = app.host.calls.borrow();
        assert_eq!(
            calls[0].0,
            "setup-plan --components ingest,console,distribution,vulns,rules,agent --hostname platform.example.com --ca quick --root-key-out /home/alice/openvibes-root-ca.key --console-port 443 --ingest-port 18423 --distribution-port 18424"
        );
        assert_eq!(calls[0].1, "pw pw pw");
    }
    assert_eq!(app.setup.phase, Phase::Running(0));
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Running(1));
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Stopped(1));
    assert!(
        app.setup.password.is_none(),
        "the password is dropped when the run stops"
    );
    let text = screen(&app);
    assert!(text.contains("dnf: no network"), "{text}");
    assert_eq!(
        app.host.calls.borrow()[2].0,
        format!("setup-step {}", Step::Postgres.name())
    );
}

/// #82: as root, Start runs at once; no password prompt is shown.
#[test]
fn root_is_not_asked_for_a_password() {
    let mut app = app(false, vec![Ok("written\n".into())]);
    app.host.root = true;
    while app.setup.row != super::setup::START_ROW {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    assert_eq!(app.setup.phase, Phase::Running(0));
    assert!(!screen(&app).contains("password"));
    assert_eq!(app.host.calls.borrow()[0].1, "", "sudo gets an empty line");
}

#[test]
fn wrong_password_mid_run_asks_again_and_resumes() {
    let mut app = app(
        false,
        vec![
            Ok("written\n".into()),
            Err(HostError::WrongPassword),
            Ok("done\tok\n".into()),
        ],
    );
    start(&mut app, "first");
    app.setup_tick();
    assert!(
        matches!(app.setup.phase, Phase::Password(_)),
        "{:?}",
        app.setup.phase
    );
    type_text(&mut app, "second");
    app.key(Key::Enter);
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Running(1));
    let calls = app.host.calls.borrow();
    assert_eq!(calls[2], ("setup-step packages".into(), "second".into()));
}

#[test]
fn three_wrong_passwords_close_the_prompt() {
    let mut app = app(
        false,
        vec![
            Err(HostError::WrongPassword),
            Err(HostError::WrongPassword),
            Err(HostError::WrongPassword),
        ],
    );
    start(&mut app, "a");
    type_text(&mut app, "b");
    app.key(Key::Enter);
    type_text(&mut app, "c");
    app.key(Key::Enter);
    assert_eq!(app.setup.phase, Phase::Form);
    assert!(screen(&app).contains("three wrong passwords"));
}

#[test]
fn the_password_is_masked() {
    let mut app = app(false, vec![]);
    while app.setup.row != super::setup::START_ROW {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    type_text(&mut app, "secret");
    let text = screen(&app);
    assert!(text.contains("******"), "{text}");
    assert!(!text.contains("secret"), "{text}");
}

#[test]
fn rules_bring_distribution_and_the_finished_screen_shows_the_login() {
    let mut app = app(false, vec![]);
    // Untick distribution: rules go too.
    while app.setup.row != 2 {
        app.key(Key::Down);
    }
    app.key(Key::Char(' '));
    assert!(
        !app.setup
            .components
            .contains(&crate::setup::plan::Component::Rules)
    );
    let mut answers: Vec<Result<String, HostError>> = vec![Ok("written\n".into())];
    for step in Step::ALL {
        answers.push(Ok(match step {
            Step::Console => "done\thttps://platform.example.com · console admin: admin, password Abc123 (shown only now; change it after logging in)\n".into(),
            _ => "done\tok\n".into(),
        }));
    }
    *app.host.answers.borrow_mut() = answers.into();
    start(&mut app, "pw");
    for _ in Step::ALL {
        app.setup_tick();
    }
    assert_eq!(app.setup.phase, Phase::Finished);
    assert!(
        screen(&app).contains("Abc123"),
        "the generated password is on the finished screen"
    );
}

const PLAN: &str = "components = [\"ingest\", \"console\", \"distribution\", \"vulns\", \"rules\", \"agent\"]\nhostname = \"platform.example.com\"\nsans = []\nca = \"quick\"\noperator = \"alice\"\n";

pub(super) fn set_up(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = app(true, answers);
    app.host.plan = PLAN.into();
    app
}

#[test]
fn a_set_up_host_offers_the_maintenance_actions() {
    let mut app = set_up(vec![]);
    for _ in 0..4 {
        app.key(Key::Tab); // Services → Configuration → Database → Health → Setup
    }
    let text = screen(&app);
    for want in [
        "c check",
        "r repair",
        "u update",
        "m components",
        "p ports",
        "x uninstall",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn repair_runs_every_step_in_repair_mode() {
    let mut app = set_up(vec![]);
    app.tab = Tab::Setup;
    app.key(Key::Char('r'));
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.setup_tick();
    assert_eq!(app.host.calls.borrow()[0].0, "setup-step packages --repair");
}

/// #87: a plan from a first install that stopped before the CA step is
/// not a set-up host: `m` offers a fresh install with a root key file.
#[test]
fn components_after_a_stopped_first_install_install_again() {
    let mut app = set_up(vec![]);
    app.host.plan = format!("{PLAN}# no ca\n");
    // The failed run's CA step wrote the default key after the TUI started.
    let home = std::env::temp_dir().join(format!("ov-87-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("openvibes-root-ca.key"), "x").unwrap();
    app.setup.home = Some(home.display().to_string());
    app.tab = Tab::Setup;
    app.key(Key::Char('m'));
    assert_eq!(app.setup.phase, Phase::Form);
    assert!(app.setup.previous.is_none(), "install, not repair");
    assert_eq!(
        app.setup.root_key_out,
        home.join("openvibes-root-ca-2.key").display().to_string(),
        "the name taken since startup is skipped"
    );
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn changing_components_installs_then_removes_the_unticked_ones() {
    let mut app = set_up(vec![]);
    app.tab = Tab::Setup;
    app.key(Key::Char('m'));
    assert_eq!(app.setup.phase, Phase::Form);
    assert_eq!(app.setup.hostname, "platform.example.com");
    while app.setup.row != 3 {
        app.key(Key::Down); // vulns
    }
    app.key(Key::Char(' '));
    start(&mut app, "pw");
    for _ in 0..Step::ALL.len() {
        app.setup_tick();
    }
    app.setup_tick();
    let calls = app.host.calls.borrow();
    assert!(
        calls[0]
            .0
            .starts_with("setup-plan --components ingest,console,distribution,rules,agent"),
        "{}",
        calls[0].0
    );
    assert_eq!(
        calls.last().unwrap().0,
        "remove-step backup --components vulns"
    );
    // The install part runs in repair mode: it may add packages, never a new CA.
    assert_eq!(calls[1].0, "setup-step packages --repair");
}

#[test]
fn update_lists_the_packages_then_runs_the_update_job() {
    let mut app = set_up(vec![]);
    app.host.packages = vec![
        PackageUpdate {
            name: "openvibes-agent".into(),
            installed: "0.1.0-1.fc44".into(),
            available: None,
        },
        PackageUpdate {
            name: "openvibes-ingest".into(),
            installed: "0.1.0-1.fc44".into(),
            available: Some("0.2.0-1.fc44".into()),
        },
    ];
    app.setup.home = Some("/home/alice".into());
    app.tab = Tab::Setup;
    app.key(Key::Char('u'));
    let text = screen(&app);
    assert!(
        text.contains("openvibes-ingest") && text.contains("0.2.0-1.fc44"),
        "{text}"
    );
    assert!(text.contains("up to date"), "{text}");
    app.key(Key::Down);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.setup_tick();
    assert_eq!(
        app.host.calls.borrow()[0].0,
        "update-step backup --backup /home/alice/openvibes-before-update.dump"
    );
}

#[test]
fn remove_everything_needs_this_hosts_name() {
    let mut answers: Vec<Result<String, HostError>> = Vec::new();
    for _ in 0..5 {
        answers.push(Ok("done\tok\n".into()));
    }
    let mut app = set_up(answers);
    app.setup.home = Some("/home/alice".into());
    app.tab = Tab::Setup;
    app.key(Key::Char('x'));
    app.key(Key::Char(' ')); // Remove everything
    while app.setup.row2 != 3 {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    assert!(
        app.message
            .clone()
            .unwrap_or_default()
            .contains("platform.example.com")
    );
    assert_eq!(app.setup.phase, Phase::Uninstall);
    app.key(Key::Up); // confirm field
    app.key(Key::Enter);
    type_text(&mut app, "platform.example.com");
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    for _ in 0..5 {
        app.setup_tick();
    }
    assert_eq!(
        app.host.calls.borrow()[0].0,
        "remove-step backup --components ingest,console,distribution,vulns,rules,agent --backup /home/alice/openvibes-backup.dump --confirm platform.example.com"
    );
    assert_eq!(app.setup.phase, Phase::Finished);
    assert!(screen(&app).contains("sudo dnf remove openvibes-admin"));
}

#[test]
fn keep_data_uninstall_sends_no_confirmation() {
    let mut app = set_up(vec![]);
    app.tab = Tab::Setup;
    app.key(Key::Char('x'));
    while app.setup.row2 != 3 {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.setup_tick();
    assert_eq!(
        app.host.calls.borrow()[0].0,
        "remove-step backup --components ingest,console,distribution,vulns,rules,agent"
    );
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

/// A set-up host whose console already moved to 8443 (board #69).
fn set_up_on_8443() -> App<SetupHost> {
    let mut app = set_up(vec![]);
    app.host.plan =
        format!("{PLAN}console_port = 8443\ningest_port = 18423\ndistribution_port = 18424\n");
    app.tab = Tab::Setup;
    app
}

#[test]
fn a_set_up_host_changes_its_ports_from_the_tui() {
    // Board #69: the port rows existed only before the first install.
    let mut app = set_up_on_8443();
    app.key(Key::Char('p'));
    assert_eq!(app.setup.phase, Phase::Form);
    assert_eq!(
        app.setup.row,
        super::setup::PORT_ROW,
        "the cursor is on the ports"
    );
    let text = screen(&app);
    assert!(
        text.contains("Console port:  8443"),
        "the saved port, not 443:\n{text}"
    );
    app.key(Key::Enter);
    app.key(Key::Backspace);
    type_text(&mut app, "4");
    app.key(Key::Enter);
    start(&mut app, "pw");
    let calls = app.host.calls.borrow();
    assert!(
        calls[0]
            .0
            .ends_with("--console-port 8444 --ingest-port 18423 --distribution-port 18424"),
        "{}",
        calls[0].0
    );
}

#[test]
fn changing_components_keeps_the_saved_ports() {
    let mut app = set_up_on_8443();
    app.key(Key::Char('m'));
    assert_eq!(app.setup.console_port, "8443");
    assert_eq!(app.setup.agent_ports, "18423, 18424");
}

#[test]
fn moving_an_agent_port_asks_for_a_second_enter() {
    let mut app = set_up_on_8443();
    app.key(Key::Char('p'));
    app.key(Key::Down); // agent ports
    app.key(Key::Enter);
    for _ in 0..5 {
        app.key(Key::Backspace);
    }
    type_text(&mut app, "18500");
    app.key(Key::Enter);
    while app.setup.row != super::setup::START_ROW {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    assert_eq!(
        app.setup.phase,
        Phase::Form,
        "not yet: the operator is warned first"
    );
    let message = app.message.clone().unwrap_or_default();
    assert!(message.contains("agents on other hosts"), "{message}");
    app.key(Key::Enter);
    assert!(
        matches!(app.setup.phase, Phase::Password(_)),
        "{:?}",
        app.setup.phase
    );
}

/// Reviewer's #106 drive: the `p` form said nothing about why the console
/// is not on 443, and showed first-install CA and root-key text.
#[test]
fn the_ports_form_says_what_holds_the_default_and_keeps_the_ca() {
    let mut app = set_up_on_8443();
    app.host.taken = vec![443];
    app.key(Key::Char('p'));
    let text = screen(&app);
    assert!(
        text.contains("Console port:  8443  (443 is in use)"),
        "{text}"
    );
    assert!(text.contains("CA:  kept (this host is set up)"), "{text}");
    assert!(!text.contains("root created here"), "{text}");
    assert!(!text.contains("Root key file"), "{text}");
    // One k from the ports skips the hidden root key row to the CA row,
    // which does not toggle on a set-up host.
    assert_eq!(app.setup.row, super::setup::PORT_ROW);
    app.key(Key::Up);
    assert_eq!(app.setup.row, super::setup::CA_ROW, "no invisible focus");
    let before = app.setup.ca;
    app.key(Key::Char(' '));
    assert_eq!(app.setup.ca, before);
}

/// Reviewer on #115, the user's own moment: the console still set to 443,
/// nginx holding 443, our console not running.
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
        let mut app = set_up(vec![]);
        app.host.plan =
            format!("{PLAN}console_port = 443\ningest_port = 18423\ndistribution_port = 18424\n");
        app.host.taken = vec![443];
        app.services = vec![status(active)];
        app.tab = Tab::Setup;
        app.key(Key::Char('p'));
        let text = screen(&app);
        assert_eq!(
            text.contains("Console port:  443  (443 is in use by another program)"),
            noted,
            "{active}:\n{text}"
        );
    }
}

/// Board #78: long step details wrapped, and the list ran off the bottom
/// (reviewer at 120x36): each step is one line, and the failed step's full
/// reason is under the list.
#[test]
fn every_step_fits_and_the_failure_is_in_full() {
    use platform_host::StepState;
    let mut app = set_up(vec![]);
    app.tab = Tab::Setup;
    app.setup.job = super::jobs::Job::Repair;
    let steps = app.setup.job.titles().len();
    let long = "a detail long enough to wrap twice on a wide terminal, ".repeat(4);
    app.setup.states = (0..steps)
        .map(|index| Some(StepState::Done(format!("{index} {long}"))))
        .collect();
    let failed = steps - 2;
    app.setup.states[failed] = Some(StepState::Failed(format!("the whole reason: {long}END")));
    app.setup.states[steps - 1] = None;
    app.setup.phase = Phase::Stopped(failed);
    let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();
    let buffer = terminal.backend().buffer();
    let text: String = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
                + "\n"
        })
        .collect();
    for title in app.setup.job.titles() {
        assert!(text.contains(title), "missing step {title:?} in\n{text}");
    }
    assert!(text.contains("END"), "the failure in full:\n{text}");
}

/// The walkthrough (2026-10-08): pressing Start froze the form while dnf ran,
/// because the turn that started the run also ran its first step before the
/// screen was drawn again.
#[test]
fn start_draws_the_checklist_before_the_first_step_runs() {
    let mut app = app(
        false,
        vec![Ok("written\n".into()), Ok("done\tinstalled\n".into())],
    );
    while app.setup.row != super::setup::START_ROW {
        app.key_then_tick(Some(Key::Down));
    }
    app.key_then_tick(Some(Key::Enter));
    type_text(&mut app, "pw");
    app.key_then_tick(Some(Key::Enter));
    // The turn that started the run ran no step: the screen comes first.
    assert_eq!(app.setup.phase, Phase::Running(0));
    let text = screen(&app);
    assert!(
        text.contains("Install packages") && text.contains("running"),
        "{text}"
    );
    assert!(text.contains("can take a few minutes"), "{text}");
    assert!(
        !text.contains("uninstall"),
        "no maintenance keys mid-run: {text}"
    );
    app.key_then_tick(None);
    assert_eq!(app.setup.phase, Phase::Running(1));
}

/// The step list is on screen while later steps run: the generated admin
/// password waits for the last screen (walkthrough, 2026-10-08).
#[test]
fn the_step_list_never_shows_the_admin_password() {
    let mut app = app(false, vec![]);
    let mut answers: Vec<Result<String, HostError>> = vec![Ok("written\n".into())];
    for step in Step::ALL {
        answers.push(Ok(match step {
            Step::Console => "done\thttps://platform.example.com · console admin: admin, password Abc123 (shown only now; change it after logging in)\n".into(),
            _ => "done\tok\n".into(),
        }));
    }
    *app.host.answers.borrow_mut() = answers.into();
    start(&mut app, "pw");
    let console = Step::ALL.iter().position(|s| *s == Step::Console).unwrap();
    for _ in 0..=console {
        app.setup_tick();
    }
    assert!(matches!(app.setup.phase, Phase::Running(_)));
    let text = screen(&app);
    assert!(!text.contains("Abc123"), "{text}");
    let row = text
        .lines()
        .find(|l| l.contains("Console and admin"))
        .unwrap();
    assert!(!row.contains('…'), "the row is not cut at 80x24: {row}");
    assert!(
        text.contains("admin account ready (password at the end)"),
        "{text}"
    );
}

/// An install run that finished, each step answering `answer(step)`.
fn finished_with(answer: impl Fn(Step) -> String) -> App<SetupHost> {
    let mut app = app(false, vec![]);
    let mut answers: Vec<Result<String, HostError>> = vec![Ok("written\n".into())];
    answers.extend(Step::ALL.into_iter().map(|step| Ok(answer(step))));
    *app.host.answers.borrow_mut() = answers.into();
    start(&mut app, "pw");
    for _ in Step::ALL {
        app.setup_tick();
    }
    assert_eq!(app.setup.phase, Phase::Finished);
    app
}

fn walkthrough_answers(step: Step) -> String {
    match step {
        Step::Console => "done\thttps://platform.example.com · console admin: admin, password Abc123 (shown only now; change it after logging in)\n".into(),
        Step::Ca => "done\troot key saved to /home/alice/openvibes-root-ca.key: keep it offline; root certificate /etc/openvibes/pki/root.crt, SHA-256 AA:BB\n".into(),
        Step::Operators => "done\talice added to openvibes-operators; log in again for it to take effect\n".into(),
        Step::Ready => "done\tready: openvibes-ingest.service openvibes-console.service\n".into(),
        _ => "done\tok\n".into(),
    }
}

/// The walkthrough (2026-10-08): the final screen was "a confusing mess of
/// text" and the agent line could not be found. Now: what to keep, labelled,
/// and what to do next; hosts are added from the console.
#[test]
fn the_finished_screen_lists_what_to_keep_and_what_next() {
    let text = screen(&finished_with(walkthrough_answers));
    for want in [
        "Setup finished",
        "Console   https://platform.example.com",
        "Sign in   admin / Abc123",
        "Root key  /home/alice/openvibes-root-ca.key",
        "Next: sign in, change the password, then add hosts under Enrollment",
        "alice can run openvibes-admin without sudo after logging in again",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(
        !text.contains("curl") && !text.contains("SHA-256"),
        "{text}"
    );
    assert!(!text.contains('…'), "nothing cut at 80x24:\n{text}");
}

#[test]
fn without_the_console_the_finished_screen_promises_no_login() {
    let text = screen(&finished_with(|step| match step {
        Step::Console => "skipped\tconsole not chosen\n".into(),
        _ => walkthrough_answers(step),
    }));
    assert!(text.contains("Setup finished"), "{text}");
    assert!(
        !text.contains("Sign in") && !text.contains("Enrollment"),
        "{text}"
    );
}

/// A detail worded in a way the screen does not know is shown as it is,
/// never dropped.
#[test]
fn an_unknown_detail_is_shown_as_it_is() {
    let text = screen(&finished_with(|step| match step {
        Step::Ca => "done\troot certificate kept from the careful CA\n".into(),
        _ => walkthrough_answers(step),
    }));
    assert!(
        text.contains("root certificate kept from the careful CA"),
        "{text}"
    );
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

/// Review (setup-ux): a step after the console's failing must not hide the
/// password generated before it; the stopped screen shows it.
#[test]
fn a_run_stopped_after_the_console_still_shows_the_password() {
    let mut app = app(false, vec![]);
    let mut answers: Vec<Result<String, HostError>> = vec![Ok("written\n".into())];
    for step in Step::ALL {
        answers.push(Ok(match step {
            Step::Services => "failed\topenvibes-ingest.service is not ready\n".into(),
            _ => walkthrough_answers(step),
        }));
    }
    *app.host.answers.borrow_mut() = answers.into();
    start(&mut app, "pw");
    for _ in Step::ALL {
        app.setup_tick();
    }
    assert!(
        matches!(app.setup.phase, Phase::Stopped(_)),
        "{:?}",
        app.setup.phase
    );
    let text = screen(&app);
    assert!(text.contains("Sign in   admin / Abc123"), "{text}");
}

/// Review (setup-ux): only a detail that carries a password is masked; a
/// check or repair shows the console row as it is.
#[test]
fn the_console_row_is_masked_only_when_it_carries_a_password() {
    let mut app = app(false, vec![]);
    let mut answers: Vec<Result<String, HostError>> = vec![Ok("written\n".into())];
    for step in Step::ALL {
        answers.push(Ok(match step {
            Step::Console => {
                "done\thttps://platform.example.com · console admin: admin · rule signer ready\n"
                    .into()
            }
            Step::Services => "failed\tstop here\n".into(),
            _ => "done\tok\n".into(),
        }));
    }
    *app.host.answers.borrow_mut() = answers.into();
    start(&mut app, "pw");
    for _ in Step::ALL {
        app.setup_tick();
    }
    let text = screen(&app);
    assert!(text.contains("https://platform.example.com"), "{text}");
    assert!(!text.contains("password at the end"), "{text}");
}

/// Review (setup-ux): what the CA step adds after the key path (e.g. that
/// the file is still owned by root) stays on the final screen.
#[test]
fn the_root_key_note_stays_on_the_finished_screen() {
    let text = screen(&finished_with(|step| {
        match step {
        Step::Ca => "done\troot key saved to /root/k.key: keep it offline (still owned by root: move it with sudo); root certificate /etc/openvibes/pki/root.crt, SHA-256 AA\n".into(),
        _ => walkthrough_answers(step),
    }
    }));
    assert!(text.contains("Root key  /root/k.key"), "{text}");
    assert!(
        text.contains("still owned by root: move it with sudo"),
        "{text}"
    );
}
