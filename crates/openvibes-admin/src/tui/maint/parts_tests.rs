//! Maintenance › Optional parts, key by key (maint2.py, maint2b.py).

use platform_host::{HostError, Step};

use crate::{
    setup::plan::{Component, ModelChoice, plan_of},
    tui::{
        app::{App, Key, Question},
        maint::Page,
        script_host::{PLAN, SetupHost, screen, set_up, type_text},
    },
};

fn page(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = set_up(answers);
    app.open_page(Page::Parts);
    app
}

/// Answers up to the model: the plan, then the 12 repairs before it.
fn until_the_model() -> Vec<Result<String, HostError>> {
    (0..13).map(|_| Ok("done\tok".to_owned())).collect()
}

/// The detail of the question asked (the bar cuts it when the line is full).
fn detail(app: &App<SetupHost>) -> String {
    match &app.question {
        Some((Question::Maint { detail, .. }, _)) => detail.clone(),
        other => panic!("no Maintenance question: {other:?}"),
    }
}

/// Down to Apply (row 2) after ticking `row` with Space.
fn tick(app: &mut App<SetupHost>, row: usize) {
    app.nav.row = row;
    app.key(Key::Char(' '));
}

fn apply(app: &mut App<SetupHost>) {
    app.nav.row = 2;
    app.key(Key::Enter);
}

fn yes_and_password(app: &mut App<SetupHost>) {
    // A removal starts on No: move to Yes first.
    if app.question.as_ref().is_some_and(|(_, yes)| !yes) {
        app.key(Key::Left);
    }
    app.key(Key::Enter);
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

/// `setup-plan` as the page must send it: the plan with the assistant added.
fn plan_with_assistant() -> String {
    let mut plan = plan_of(PLAN).unwrap();
    plan.components.push(Component::Assistant);
    plan.model = ModelChoice::Fetch;
    format!("setup-plan {}", plan.args().join(" "))
}

#[test]
fn the_page_shows_what_is_installed() {
    let app = page(vec![]);
    let text = screen(&app);
    for want in [
        "[x] Agent on this host",
        "watch this host too",
        "[ ] Assistant",
        "local AI helper · 2.7 GB download",
        "nothing changed yet",
        "Space  Select/deselect",
        "Enter  Confirm",
        "The agent reports this host's own findings and alarms.",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn ticking_the_assistant_says_what_apply_does() {
    let mut app = page(vec![]);
    app.key(Key::Down);
    assert!(screen(&app).contains("Answers questions about your findings"));
    app.key(Key::Char(' '));
    let text = screen(&app);
    assert!(
        text.contains("[x] Assistant") && text.contains("install the assistant"),
        "{text}"
    );
    app.key(Key::Down);
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("Install the assistant?") && text.contains("2.7 GB"),
        "{text}"
    );
}

#[test]
fn apply_saves_the_whole_plan_then_repairs() {
    let mut app = page(vec![]);
    tick(&mut app, 1);
    apply(&mut app);
    yes_and_password(&mut app);
    let calls = calls(&app);
    assert_eq!(calls[0], plan_with_assistant());
    assert!(
        calls[0].starts_with(
            "setup-plan --components ingest,console,distribution,vulns,rules,agent,assistant \
             --hostname platform.example.com --ca quick"
        ) && calls[0].ends_with("--model fetch"),
        "{}",
        calls[0]
    );
    assert_eq!(calls[1], "setup-step packages --repair");
    // Every step once; the model comes before Ready on this page.
    let mut repairs: Vec<&String> = calls
        .iter()
        .filter(|c| c.starts_with("setup-step"))
        .collect();
    repairs.sort();
    let mut all: Vec<String> = Step::ALL
        .iter()
        .map(|s| format!("setup-step {} --repair", s.name()))
        .collect();
    all.sort();
    assert_eq!(repairs, all.iter().collect::<Vec<_>>());
    assert_eq!(calls.last().unwrap(), "setup-status");
    let text = screen(&app);
    for want in [
        "Installing the assistant",
        "Save the choice",
        "Install the assistant",
        "Download the model",
        "Ready",
        "Assistant installed · ask it in the console (",
        "Enter  Back",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    app.key(Key::Enter);
    assert_ne!(app.nav.screen, crate::tui::nav::Screen::Maint(Page::Parts));
}

#[test]
fn a_model_that_is_not_downloaded_is_a_note_not_a_failure() {
    // plan, 12 repairs (packages..agent), then the model.
    let mut answers = until_the_model();
    answers.push(Ok("skipped\tthe model is not here yet".into()));
    let mut app = page(answers);
    tick(&mut app, 1);
    apply(&mut app);
    yes_and_password(&mut app);
    let text = screen(&app);
    assert!(
        text.contains("– Download the model  the model is not here yet"),
        "{text}"
    );
    assert!(
        text.contains("Assistant installed · ask it in the console"),
        "{text}"
    );
    assert!(!text.contains('✗'), "{text}");

    let mut answers = until_the_model();
    answers.push(Ok("waiting\tdownload it by hand".into()));
    let mut app = page(answers);
    tick(&mut app, 1);
    apply(&mut app);
    yes_and_password(&mut app);
    let text = screen(&app);
    assert!(
        text.contains("– Download the model  download it by hand"),
        "{text}"
    );
    assert!(
        text.contains("Assistant installed · ask it in the console"),
        "{text}"
    );
    assert!(!text.contains('✗'), "{text}");
}

#[test]
fn unticking_the_agent_asks_starting_on_no() {
    let mut app = page(vec![]);
    tick(&mut app, 0);
    let text = screen(&app);
    assert!(
        text.contains("remove the agent")
            && text.contains("Removing the agent also removes its data from this host."),
        "{text}"
    );
    apply(&mut app);
    let text = screen(&app);
    assert!(text.contains("Remove the agent?"), "{text}");
    assert_eq!(detail(&app), "its data goes too");
    assert!(text.contains("[ Yes ]  No"), "{text}");
    app.key(Key::Enter);
    assert!(app.question.is_none() && app.asking.is_none());
    assert!(calls(&app).is_empty());
}

#[test]
fn removing_the_agent_runs_remove_steps_for_the_agent_only() {
    let mut app = page(vec![]);
    tick(&mut app, 0);
    apply(&mut app);
    yes_and_password(&mut app);
    let calls = calls(&app);
    assert!(calls[0].starts_with("setup-plan "), "{}", calls[0]);
    assert!(
        !calls[0].contains("agent,") && !calls[0].contains(",agent"),
        "{}",
        calls[0]
    );
    for step in ["backup", "stop", "firewall", "packages", "purge", "admin"] {
        let want = format!("remove-step {step} --components agent");
        assert!(calls.contains(&want), "missing {want:?} in {calls:?}");
    }
    assert!(!calls.iter().any(|c| c.contains("--backup")));
    // Removal only: every Repair step exactly once, then the status.
    assert_eq!(
        calls.iter().filter(|c| c.starts_with("setup-step")).count(),
        Step::ALL.len()
    );
    let text = screen(&app);
    for want in [
        "Removing the agent",
        "Stop the agent",
        "Remove the agent",
        "Remove its data",
        "Agent removed · nothing of it is left on this host (",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn removing_the_assistant_asks_and_names_its_model() {
    let mut app = set_up(vec![]);
    app.host.plan =
        format!("{PLAN}model = \"fetch\"\n").replace("\"agent\"]", "\"agent\", \"assistant\"]");
    app.open_page(Page::Parts);
    assert!(screen(&app).contains("[x] Assistant"));
    tick(&mut app, 1);
    assert!(screen(&app).contains("Removing the assistant also removes its data"));
    apply(&mut app);
    let text = screen(&app);
    assert!(text.contains("Remove the assistant?"), "{text}");
    assert_eq!(detail(&app), "its data goes too");
}

#[test]
fn both_removed_use_one_component_list() {
    let mut app = set_up(vec![]);
    app.host.plan = PLAN.replace("\"agent\"]", "\"agent\", \"assistant\"]");
    app.open_page(Page::Parts);
    tick(&mut app, 0);
    tick(&mut app, 1);
    apply(&mut app);
    yes_and_password(&mut app);
    let calls = calls(&app);
    assert!(calls.contains(&"remove-step purge --components agent,assistant".to_owned()));
    assert!(screen(&app).contains("Remove the agent and the assistant"));
}

#[test]
fn nothing_changed_enter_does_nothing() {
    let mut app = page(vec![]);
    apply(&mut app);
    assert!(app.question.is_none() && app.asking.is_none());
    assert!(calls(&app).is_empty());
}

#[test]
fn adding_only_the_agent_leaves_the_model_to_ready() {
    let mut app = set_up(vec![]);
    app.host.plan = PLAN.replace(", \"agent\"]", "]");
    app.open_page(Page::Parts);
    assert!(screen(&app).contains("[ ] Agent on this host"));
    tick(&mut app, 0);
    apply(&mut app);
    assert!(screen(&app).contains("Install the agent?"));
    yes_and_password(&mut app);
    let text = screen(&app);
    assert!(
        text.contains("Agent installed · this host reports to the console"),
        "{text}"
    );
    assert!(!text.contains("Download the model"), "{text}");
    assert_eq!(
        calls(&app)
            .iter()
            .filter(|c| c.starts_with("setup-step"))
            .count(),
        Step::ALL.len()
    );
}

#[test]
fn every_question_fits_the_bar_with_its_buttons() {
    type Setup = fn(&mut App<SetupHost>);
    let cases: [(Setup, &[usize], &str, &str); 5] = [
        (|_| {}, &[1], "Install the assistant?", "2.7 GB"),
        (
            |a| a.host.plan = PLAN.replace(", \"agent\"]", "]"),
            &[0],
            "Install the agent?",
            "watch this host too",
        ),
        (
            |a| a.host.plan = PLAN.replace(", \"agent\"]", "]"),
            &[0, 1],
            "Install both parts?",
            "2.7 GB",
        ),
        (|_| {}, &[0], "Remove the agent?", "its data goes too"),
        (
            |a| a.host.plan = PLAN.replace("\"agent\"]", "\"agent\", \"assistant\"]"),
            &[0, 1],
            "Remove both parts?",
            "their data goes too",
        ),
    ];
    for (setup, ticks, text, detail) in cases {
        let mut app = set_up(vec![]);
        setup(&mut app);
        app.open_page(Page::Parts);
        for row in ticks {
            tick(&mut app, *row);
        }
        apply(&mut app);
        let bar = screen(&app);
        for want in [text, detail, "Yes", "No"] {
            assert!(bar.contains(want), "missing {want:?} in\n{bar}");
        }
    }
}
