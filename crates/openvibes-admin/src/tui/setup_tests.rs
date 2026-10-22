//! The Setup tab against a scripted host.

use platform_host::{HostError, Step};
use ratatui::{Terminal, backend::TestBackend};

use super::{
    app::{App, Key, Tab},
    nav::Screen,
    render,
    script_host::*,
    setup::Phase,
};

#[test]
fn a_new_host_opens_on_setup_with_the_components() {
    let app = app(false, vec![]);
    assert_eq!(app.tab, Tab::Setup);
    let text = screen(&app);
    for want in [
        "· Install",
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
    assert_eq!(app(true, vec![]).nav.screen, Screen::Home);
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
    // A fresh host has nowhere to go back to: the stopped run offers q.
    assert!(text.contains("q quit"), "{text}");
    app.key(Key::Char('q'));
    assert!(app.quit);
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

#[test]
fn after_a_failed_step_r_retries() {
    let mut app = app(
        false,
        vec![Ok("written\n".into()), Ok("failed\tdnf\n".into())],
    );
    start(&mut app, "pw");
    app.setup_tick();
    assert_eq!(app.setup.phase, Phase::Stopped(0));
    app.key(Key::Char('r'));
    assert!(matches!(app.setup.phase, Phase::Password(_)));
}

/// Board #78: long step details wrapped, and the list ran off the bottom
/// (reviewer at 120x36): each step is one line, and the failed step's full
/// reason is under the list.
#[test]
fn every_step_fits_and_the_failure_is_in_full() {
    use platform_host::StepState;
    let mut app = app(false, vec![]);
    let steps = Step::ALL.len();
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
    for title in Step::ALL.map(|step| step.title()) {
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

#[test]
fn a_failed_model_download_still_ends_on_the_finished_screen_with_the_login() {
    let mut app = app(false, vec![]);
    let mut answers: Vec<Result<String, HostError>> = vec![Ok("written\n".into())];
    for step in Step::ALL {
        answers.push(Ok(match step {
            Step::Console => "done\thttps://platform.example.com · console admin: admin, password Abc123 (shown only now; change it after logging in)\n".into(),
            Step::AssistantModel => "failed\tthe model download failed (offline: see the offline install guide)\n".into(),
            _ => "done\tok\n".into(),
        }));
    }
    *app.host.answers.borrow_mut() = answers.into();
    start(&mut app, "pw");
    for _ in Step::ALL {
        app.setup_tick();
    }
    assert_eq!(app.setup.phase, Phase::Finished);
    let text = screen(&app);
    assert!(
        text.contains("Abc123") && text.contains("https://platform.example.com"),
        "{text}"
    );
    assert!(text.contains("model download failed"), "{text}");
}

#[test]
fn a_declined_model_is_named_on_the_finished_screen() {
    let mut app = app(false, vec![]);
    let mut answers: Vec<Result<String, HostError>> = vec![Ok("written\n".into())];
    for step in Step::ALL {
        answers.push(Ok(match step {
            Step::AssistantModel => "skipped\tassistant: off until its model is installed; turn the assistant on in Setup again to download it\n".into(),
            _ => "done\tok\n".into(),
        }));
    }
    *app.host.answers.borrow_mut() = answers.into();
    start(&mut app, "pw");
    for _ in Step::ALL {
        app.setup_tick();
    }
    assert_eq!(app.setup.phase, Phase::Finished);
    assert!(screen(&app).contains("assistant: off until its model is installed"));
}
