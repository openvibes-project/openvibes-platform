//! Work in the background: the password in the bar, wrong passwords,
//! stopping at a failure, the rescue, and quitting while it runs.

use std::{cell::RefCell, rc::Rc, sync::mpsc, time::Instant};

use platform_host::{HostError, Step, StepState, UpdateStep};

use super::{
    app::{Key, Question},
    run::{Call, Kind, Progress, Rescue, Work},
    script_host::{SetupHost, screen, set_up, type_text},
};

type Sender = Rc<RefCell<Option<mpsc::Sender<Progress>>>>;

fn fix(calls: Vec<Call>) -> Work {
    Work::new(Kind::Fix, calls)
}

/// A worker whose progress the test sends by hand.
fn by_hand(app: &mut super::app::App<SetupHost>) -> Sender {
    let sender: Sender = Rc::new(RefCell::new(None));
    let keep = sender.clone();
    app.worker = Some(Box::new(move |_work, _from, _secret| {
        let (tx, rx) = mpsc::channel();
        *keep.borrow_mut() = Some(tx);
        rx
    }));
    sender
}

fn send(sender: &Sender, index: usize) {
    sender
        .borrow()
        .as_ref()
        .unwrap()
        .send(Progress {
            index,
            result: Ok("done\tok\n".into()),
        })
        .unwrap();
}

#[test]
fn the_password_is_asked_in_the_bar_then_every_call_runs_with_it() {
    let mut app = set_up(vec![Ok("done\tok\n".into()), Ok("done\tok\n".into())]);
    app.begin(
        fix(vec![
            Call::Repair(Step::Packages),
            Call::Repair(Step::Postgres),
        ]),
        0,
    );
    let text = screen(&app);
    assert!(text.contains("Your password (sudo):"), "{text}");
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(
        app.asking.is_none(),
        "the prompt is gone once Enter is pressed"
    );
    assert_eq!(
        *app.host.calls.borrow(),
        [
            ("setup-step packages --repair".to_owned(), "pw".to_owned()),
            ("setup-step postgres --repair".to_owned(), "pw".to_owned()),
        ]
    );
    assert!(app.run.as_ref().unwrap().ok());
}

#[test]
fn a_wrong_password_is_said_in_the_bar_with_the_tries_left_and_the_run_resumes() {
    let mut app = set_up(vec![Err(HostError::WrongPassword), Ok("done\tok\n".into())]);
    app.begin(fix(vec![Call::Repair(Step::Packages)]), 0);
    type_text(&mut app, "bad");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Wrong password, 2 tries left."), "{text}");
    type_text(&mut app, "good");
    app.key(Key::Enter);
    assert_eq!(app.host.calls.borrow().last().unwrap().1, "good");
    assert!(app.run.as_ref().unwrap().ok());
}

#[test]
fn three_wrong_passwords_stop_the_run_and_nothing_more_runs() {
    let answers = (0..3).map(|_| Err(HostError::WrongPassword)).collect();
    let mut app = set_up(answers);
    app.begin(
        fix(vec![
            Call::Repair(Step::Packages),
            Call::Repair(Step::Postgres),
        ]),
        0,
    );
    for _ in 0..3 {
        type_text(&mut app, "bad");
        app.key(Key::Enter);
    }
    assert!(app.asking.is_none());
    assert_eq!(app.host.calls.borrow().len(), 3);
    let run = app.run.as_ref().unwrap();
    assert!(!run.running() && !run.ok());
    assert!(
        run.states[0]
            .as_ref()
            .unwrap()
            .detail()
            .contains("three wrong passwords")
    );
}

#[test]
fn a_run_stops_at_the_first_step_that_fails() {
    let mut app = set_up(vec![Ok("failed\tdisk full\n".into())]);
    app.begin(
        fix(vec![
            Call::Repair(Step::Packages),
            Call::Repair(Step::Postgres),
        ]),
        0,
    );
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(
        app.host.calls.borrow().len(),
        1,
        "nothing after the failure"
    );
    let run = app.run.as_ref().unwrap();
    assert_eq!(run.stopped_at(), Some(0));
    assert_eq!(run.states[0], Some(StepState::Failed("disk full".into())));
}

#[test]
fn a_failure_the_rescue_covers_runs_the_rescue_with_the_same_password() {
    let mut app = set_up(vec![
        Ok("done\tok\n".into()),
        Ok("done\tok\n".into()),
        Ok("failed\ttimed out\n".into()),
    ]);
    let update = |step| Call::Update(step, Vec::new());
    app.begin(
        Work {
            kind: Kind::Update { to: "0.2.9".into() },
            calls: vec![
                update(UpdateStep::Backup),
                update(UpdateStep::Stop),
                update(UpdateStep::Upgrade),
            ],
            rescue: Some(Rescue {
                from: 1,
                to: 3,
                calls: vec![update(UpdateStep::Start)],
            }),
        },
        0,
    );
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls = app.host.calls.borrow();
    assert_eq!(calls[3], ("update-step start".to_owned(), "pw".to_owned()));
    let run = app.run.as_ref().unwrap();
    assert_eq!(run.stopped_at(), Some(2));
    assert_eq!(run.rescued(0), Some(&StepState::Done("ok".into())));
    assert!(!run.running());
}

#[test]
fn root_is_not_asked_for_a_password() {
    let mut app = set_up(vec![]);
    app.host.root = true;
    app.begin(fix(vec![Call::Repair(Step::Packages)]), 0);
    assert!(app.asking.is_none());
    assert_eq!(
        *app.host.calls.borrow(),
        [("setup-step packages --repair".to_owned(), String::new())]
    );
}

#[test]
fn with_a_worker_the_screen_keeps_drawing_while_the_step_runs() {
    let mut app = set_up(vec![]);
    let sender = by_hand(&mut app);
    app.begin(
        fix(vec![
            Call::Repair(Step::Packages),
            Call::Repair(Step::Postgres),
        ]),
        0,
    );
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(app.run.as_ref().unwrap().running());
    let text = screen(&app);
    assert!(text.contains("Repairing…"), "Home says what runs:\n{text}");
    send(&sender, 0);
    app.tick(Instant::now());
    assert_eq!(
        app.run.as_ref().unwrap().states[0],
        Some(StepState::Done("ok".into()))
    );
    assert_eq!(app.run.as_ref().unwrap().current(), Some(1));
    send(&sender, 1);
    app.tick(Instant::now());
    assert!(app.run.as_ref().unwrap().ok());
    assert!(
        app.host.calls.borrow().is_empty(),
        "the worker ran them, not the TUI's thread"
    );
    assert!(screen(&app).contains("✓ Repaired"), "Home shows the result");
}

#[test]
fn q_while_work_runs_asks_and_quits_once_it_is_done() {
    let mut app = set_up(vec![]);
    let sender = by_hand(&mut app);
    app.begin(fix(vec![Call::Repair(Step::Packages)]), 0);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.key(Key::Char('q'));
    assert!(matches!(app.question, Some((Question::Quit, true))));
    assert!(screen(&app).contains("Quit when it is done?"));
    app.key(Key::Enter);
    assert!(!app.quit, "the work goes on");
    assert!(screen(&app).contains("Quits when it is done"));
    send(&sender, 0);
    app.tick(Instant::now());
    assert!(app.quit);
}

#[test]
fn ctrl_c_while_work_runs_asks_and_a_second_ctrl_c_quits_at_once() {
    let mut app = set_up(vec![]);
    let _sender = by_hand(&mut app);
    app.begin(fix(vec![Call::Repair(Step::Packages)]), 0);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.interrupt();
    assert!(!app.quit && matches!(app.question, Some((Question::Quit, _))));
    app.interrupt();
    assert!(app.quit);
    let mut idle = set_up(vec![]);
    idle.interrupt();
    assert!(idle.quit, "nothing running: Ctrl+C quits");
}
