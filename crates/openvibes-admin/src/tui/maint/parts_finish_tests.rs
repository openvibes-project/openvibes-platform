//! Maintenance › Optional parts: a part out of the plan whose removal did
//! not finish (its package or data folder is still here).

use platform_host::PackageUpdate;

use crate::tui::{
    app::{App, Key},
    maint::Page,
    script_host::{PLAN, SetupHost, screen, set_up, type_text},
};

/// The plan without the agent, and the page opened.
fn page(prepare: impl FnOnce(&mut App<SetupHost>)) -> App<SetupHost> {
    let mut app = set_up(vec![]);
    app.host.plan = PLAN.replace(", \"agent\"]", "]");
    prepare(&mut app);
    app.open_page(Page::Parts);
    app
}

fn agent_package(app: &mut App<SetupHost>) {
    app.packages = Some(Ok(vec![PackageUpdate {
        name: "openvibes-agent".into(),
        installed: "0.2.9-1".into(),
        available: None,
    }]));
}

#[test]
fn a_part_left_behind_says_its_removal_did_not_finish() {
    let app = page(agent_package);
    let text = screen(&app);
    let agent = text
        .lines()
        .find(|l| l.contains("Agent on this host"))
        .unwrap();
    assert!(
        agent.contains("[ ]") && agent.contains("removal not finished"),
        "{text}"
    );
    assert!(text.contains("finish removing the agent"), "{text}");
    // Its data folder alone is enough.
    let app = page(|app| {
        std::fs::create_dir_all(app.root.join("var/lib/openvibes-llm")).unwrap();
    });
    let text = screen(&app);
    let assistant = text.lines().find(|l| l.contains("Assistant")).unwrap();
    assert!(assistant.contains("removal not finished"), "{text}");
    // Nothing left: nothing to finish.
    let text = screen(&page(|_| {}));
    assert!(!text.contains("removal not finished"), "{text}");
    assert!(text.contains("nothing changed yet"), "{text}");
}

#[test]
fn apply_finishes_the_removal_without_saving_a_choice() {
    let mut app = page(agent_package);
    app.nav.row = 2;
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Remove the agent?"), "{text}");
    assert!(
        app.question.as_ref().is_some_and(|(_, yes)| !yes),
        "starts on No"
    );
    app.key(Key::Left);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls: Vec<String> = app
        .host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect();
    assert!(
        !calls.iter().any(|c| c.starts_with("setup-plan")),
        "{calls:?}"
    );
    let removes: Vec<&String> = calls
        .iter()
        .filter(|c| c.starts_with("remove-step"))
        .collect();
    let want: Vec<String> = ["backup", "stop", "firewall", "packages", "purge", "admin"]
        .iter()
        .map(|s| format!("remove-step {s} --components agent"))
        .collect();
    assert_eq!(removes, want.iter().collect::<Vec<_>>());
    assert_eq!(calls.last().unwrap(), "setup-status");
    let text = screen(&app);
    assert!(!text.contains("Save the choice"), "{text}");
    assert!(
        text.contains("Agent removed · nothing of it is left on this host"),
        "{text}"
    ); // Back, and in again: finished, not "removal not finished" from the
    // package list read at start.
    app.key(Key::Enter);
    app.open_page(Page::Parts);
    let text = screen(&app);
    assert!(!text.contains("removal not finished"), "{text}");
}
