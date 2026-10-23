//! Installing and Finished on the worker's rows (install.py), driven with
//! the script host: one answer per helper call.

use platform_host::{HostError, Step, StepState};

use super::{Ca, Install, Stage, finished::finished_rows};
use crate::tui::{
    app::{App, Key},
    nav::Screen,
    script_host::{SetupHost, app, screen, set_up, type_text},
};

fn ok() -> Result<String, HostError> {
    Ok("done\tok".into())
}

fn fresh(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = app(false, answers);
    app.install = Install::new("limebox.lan".into(), Some("/home/alice".into()));
    app
}

/// Start, then the password.
fn go(app: &mut App<SetupHost>) {
    app.start_install();
    type_text(app, "pw");
    app.key(Key::Enter);
}

fn calls(app: &App<SetupHost>) -> Vec<String> {
    app.host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect()
}

fn titles(install: &Install) -> Vec<String> {
    install.work().labels.into_iter().map(|(t, _)| t).collect()
}

#[test]
fn installing_keeps_the_empty_line_under_the_heading() {
    let mut app = fresh(vec![]);
    app.install.agent = false;
    app.nav.screen = Screen::Install(Stage::Running);
    app.run = Some(crate::tui::run::Run::new(
        app.install.work(),
        std::time::Instant::now(),
    ));
    let text = screen(&app);
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.contains("━━ Installing"))
        .unwrap();
    assert!(lines[at + 1].trim().is_empty(), "{text}");
    assert!(lines[at + 2].contains("Packages"), "{text}");
    assert!(text.contains("Ready"), "{text}");
}

#[test]
fn a_failure_with_twelve_rows_keeps_its_whole_reason_at_80x24() {
    let mut app = fresh(vec![
        ok(),
        ok(),
        Ok("failed\tport 443 is in use by nginx".into()),
    ]);
    app.install.assistant = true;
    go(&mut app);
    let text = screen(&app);
    assert_eq!(app.install.work().labels.len(), 12);
    assert!(text.contains("✗ PostgreSQL"), "{text}");
    assert!(text.contains("port 443 is in use by nginx"), "{text}");
    assert!(text.contains("Try again goes on from this step."), "{text}");
    assert!(text.contains("Enter  Try again"), "{text}");
}

#[test]
fn install_rows_group_the_steps() {
    let mut install = Install::new("limebox.lan".into(), None);
    install.agent = false;
    assert_eq!(
        titles(&install),
        [
            "Packages",
            "PostgreSQL",
            "Database",
            "Certificate authority",
            "Certificates",
            "Console",
            "Services",
            "Firewall",
            "Baseline rules",
            "Ready"
        ]
    );
    install.agent = true;
    install.assistant = true;
    let all = titles(&install);
    assert_eq!(all.len(), 12);
    assert_eq!(all[9], "Agent on this host");
    assert_eq!(all[11], "Assistant");
}

#[test]
fn install_runs_plan_then_every_step() {
    let mut app = fresh(vec![]);
    app.install.assistant = true;
    go(&mut app);
    let calls = calls(&app);
    assert!(calls[0].starts_with("setup-plan --components ingest,console"));
    assert!(calls[0].contains("--model fetch"));
    assert_eq!(calls[1], "setup-step packages");
    assert!(calls.iter().all(|c| !c.contains("--repair")));
    assert_eq!(calls.last().unwrap(), "setup-step assistant-model");
    let steps: Vec<&str> = calls[1..]
        .iter()
        .map(|c| c.strip_prefix("setup-step ").unwrap())
        .collect();
    let all: Vec<&str> = Step::ALL.iter().map(|s| s.name()).collect();
    assert_eq!(steps, all);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Finished));
}

#[test]
fn installing_shows_current_row_and_step_count() {
    let mut app = fresh(vec![]);
    app.install.agent = false;
    // The plan and Packages are done; PostgreSQL is running.
    let mut run = crate::tui::run::Run::new(app.install.work(), std::time::Instant::now());
    run.states[0] = Some(StepState::Done(String::new()));
    run.states[1] = Some(StepState::Done(String::new()));
    app.nav.screen = Screen::Install(Stage::Running);
    app.run = Some(run);
    let text = screen(&app);
    assert!(text.contains("Installing"), "{text}");
    assert!(text.contains("Step 2 of 10: PostgreSQL"), "{text}");
}

fn fail_at_postgres() -> App<SetupHost> {
    let mut app = fresh(vec![ok(), ok(), Ok("failed\tport in use".into())]);
    app.install.agent = false;
    go(&mut app);
    app
}

#[test]
fn failure_offers_try_again_and_resumes_at_that_step() {
    let mut app = fail_at_postgres();
    let text = screen(&app);
    assert!(text.contains("✗ PostgreSQL"), "{text}");
    assert!(text.contains("port in use"), "{text}");
    assert!(text.contains("Enter  Try again"), "{text}");
    assert!(text.contains("Esc  Back"), "{text}");
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls = calls(&app);
    assert_eq!(calls[3], "setup-step postgres", "{calls:?}");
    assert_eq!(
        calls.iter().filter(|c| *c == "setup-step packages").count(),
        1
    );
    assert_eq!(app.nav.screen, Screen::Install(Stage::Finished));
}

#[test]
fn esc_after_failure_goes_to_review_without_ca_and_home_with_ca() {
    let mut app = fail_at_postgres();
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Step(4)));
    let mut app = set_up(vec![ok(), ok(), Ok("failed\tno".into())]);
    app.install = Install::new("limebox.lan".into(), None);
    go(&mut app);
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Home);
}

fn states(ca: &str, console: &str) -> Vec<Option<StepState>> {
    Step::ALL
        .iter()
        .map(|s| match s {
            Step::Ca => Some(StepState::Done(ca.into())),
            Step::Console => Some(StepState::Done(console.into())),
            _ => None,
        })
        .collect()
}

fn text(rows: Vec<crate::tui::ui::list::Row>) -> String {
    use crate::tui::ui::list::Row;
    rows.into_iter()
        .map(|r| match r {
            Row::Entry { name, value } => {
                let n: String = name.iter().map(|s| s.content.as_ref()).collect();
                let v: String = value.iter().map(|s| s.content.as_ref()).collect();
                format!("{n}|{v}\n")
            }
            Row::Heading { text, .. } => text,
        })
        .collect()
}

const CONSOLE: &str = "https://limebox.lan · console admin: admin, password Kq7-vR2p-Xw9m (shown only now; change it after logging in)";

#[test]
fn installing_hides_the_generated_password_until_the_end() {
    use crate::tui::run::Call;
    let mut app = fresh(vec![]);
    app.install.agent = false;
    let mut run = crate::tui::run::Run::new(app.install.work(), std::time::Instant::now());
    let console = run
        .work
        .calls
        .iter()
        .position(|c| *c == Call::Setup(Step::Console))
        .unwrap();
    run.states[console] = Some(StepState::Done(CONSOLE.into()));
    app.nav.screen = Screen::Install(Stage::Running);
    app.run = Some(run);
    let text = screen(&app);
    assert!(!text.contains("Kq7-vR2p-Xw9m"), "{text}");
}

#[test]
fn finished_own_root_shows_root_key_row() {
    let s = states(
        "root key saved to /home/a/root.key: keep it offline; root certificate x",
        CONSOLE,
    );
    let t = text(finished_rows(&s, None));
    assert!(t.contains("Open the console|https://limebox.lan\n"), "{t}");
    assert!(t.contains("Sign in as|admin"), "{t}");
    assert!(
        t.contains("Password|Kq7-vR2p-Xw9m   shown only now: write it down"),
        "{t}"
    );
    assert!(t.contains("Root key|/home/a/root.key"), "{t}");
    assert!(
        t.contains("move it to a USB stick and keep it offline"),
        "{t}"
    );
    assert!(!t.contains("Certificates"), "{t}");
}

#[test]
fn finished_own_ca_shows_signed_by() {
    let s = states("root certificate /etc/x, SHA-256 AB", CONSOLE);
    let t = text(finished_rows(&s, Some("Lime Lab Root CA")));
    assert!(t.contains("Certificates|signed by Lime Lab Root CA"), "{t}");
    assert!(
        t.contains("browsers that trust your CA show no warning"),
        "{t}"
    );
    assert!(!t.contains("Root key"), "{t}");
}

#[test]
fn finished_console_port_in_address() {
    let s = states(
        "root certificate x",
        "https://limebox.lan:8443 · console admin: admin",
    );
    let t = text(finished_rows(&s, None));
    assert!(t.contains("https://limebox.lan:8443"), "{t}");
}

#[test]
fn finished_enter_goes_home() {
    let mut app = fresh(vec![]);
    go(&mut app);
    let text = screen(&app);
    assert!(text.contains("OpenVIBES is installed"), "{text}");
    assert!(text.contains("Enter  Continue to Home"), "{text}");
    assert!(
        text.contains("limebox") || text.contains("Install"),
        "{text}"
    );
    // Read before or while installing: Home's count must not show it.
    app.database.health = vec![crate::tui::database::Check {
        problem: true,
        text: "stale".into(),
    }];
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Home);
    assert!(
        app.database.health.iter().all(|c| c.text != "stale"),
        "{:?}",
        app.database.health
    );
}

#[test]
fn quick_plan_carries_the_root_key_and_careful_does_not() {
    let mut install = Install::new("limebox.lan".into(), Some("/home/alice".into()));
    install.ca = Ca::OpenVibes;
    assert!(
        install
            .plan_args()
            .join(" ")
            .contains("--ca quick --root-key-out /home/alice/")
    );
    install.ca = Ca::Own;
    let args = install.plan_args().join(" ");
    assert!(
        args.contains("--ca careful") && !args.contains("--root-key-out"),
        "{args}"
    );
    assert!(args.ends_with("--console-port 443 --ingest-port 18423 --distribution-port 18424"));
}

/// The one-time secret on the real 80×24 Finished screen (spec §11): the
/// Password row and the Next line that says to change it.
#[test]
fn finished_screen_shows_the_password_once_and_next() {
    let mut answers = vec![ok()];
    answers.extend(Step::ALL.iter().map(|step| match step {
        Step::Console => Ok(format!("done\t{CONSOLE}")),
        _ => ok(),
    }));
    let mut app = fresh(answers);
    go(&mut app);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Finished));
    let text = screen(&app);
    assert!(text.contains("Password"), "{text}");
    assert!(text.contains("Kq7-vR2p-Xw9m"), "{text}");
    assert!(text.contains("shown only now: write it down"), "{text}");
    assert!(
        text.contains("Next: sign in, change the password, then add hosts under Enrollment."),
        "{text}"
    );
}
