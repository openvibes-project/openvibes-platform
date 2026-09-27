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

struct SetupHost {
    set_up: bool,
    /// What each privileged call returns, in order.
    answers: RefCell<VecDeque<Result<String, HostError>>>,
    /// (verb, password) of each call.
    calls: RefCell<Vec<(String, String)>>,
    /// `setup.toml`'s text; empty: not set up.
    plan: String,
    packages: Vec<PackageUpdate>,
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
    fn packages(&self) -> Result<Vec<PackageUpdate>, HostError> {
        Ok(self.packages.clone())
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
    let mut app = App::new(SetupHost {
        set_up,
        answers: RefCell::new(answers.into()),
        calls: RefCell::new(Vec::new()),
        plan: String::new(),
        packages: Vec::new(),
    });
    app.setup.hostname = "platform.example.com".into();
    app.setup.root_key_out = "/home/alice/openvibes-root-ca.key".into();
    app
}

fn screen(app: &App<SetupHost>) -> String {
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

fn type_text(app: &mut App<SetupHost>, text: &str) {
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
        "[x] ingest",
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
            "setup-plan --components ingest,console,distribution,vulns,rules,agent --hostname platform.example.com --ca quick --root-key-out /home/alice/openvibes-root-ca.key"
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

fn set_up(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = app(true, answers);
    app.host.plan = PLAN.into();
    app
}

#[test]
fn a_set_up_host_offers_the_maintenance_actions() {
    let mut app = set_up(vec![]);
    app.key(Key::Tab);
    app.key(Key::Tab); // Services → Configuration → Setup
    let text = screen(&app);
    for want in [
        "c check",
        "r repair",
        "u update",
        "m change components",
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
}
