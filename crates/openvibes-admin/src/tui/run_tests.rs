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
            kind: Kind::Update {
                to: "0.2.9".into(),
                others: None,
            },
            calls: vec![
                update(UpdateStep::Backup),
                update(UpdateStep::Stop),
                update(UpdateStep::Upgrade),
            ],
            labels: (0..3).map(|i| (String::new(), i..i + 1)).collect(),
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

fn start_by_hand(calls: usize) -> (super::app::App<SetupHost>, Sender) {
    let mut app = set_up(vec![]);
    let sender = by_hand(&mut app);
    app.begin(fix(vec![Call::Repair(Step::Packages); calls]), 0);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    (app, sender)
}

#[test]
fn a_worker_that_dies_after_step_0_fails_the_next_step() {
    let (mut app, sender) = start_by_hand(2);
    send(&sender, 0);
    sender.borrow_mut().take();
    app.tick(Instant::now());
    let run = app.run.as_ref().unwrap();
    assert!(!run.running());
    assert_eq!(run.states[0], Some(StepState::Done("ok".into())));
    assert_eq!(run.stopped_at(), Some(1));
    assert!(
        run.states[1]
            .as_ref()
            .unwrap()
            .detail()
            .contains("stopped unexpectedly")
    );
}

#[test]
fn a_worker_that_dies_at_once_fails_the_first_step() {
    let (mut app, sender) = start_by_hand(2);
    sender.borrow_mut().take();
    app.tick(Instant::now());
    let run = app.run.as_ref().unwrap();
    assert_eq!(run.stopped_at(), Some(0));
    assert!(!run.ok());
}

#[test]
fn ctrl_c_after_yes_to_quit_when_done_quits_at_once() {
    let (mut app, _sender) = start_by_hand(1);
    app.interrupt();
    app.key(Key::Enter);
    assert!(app.quit_when_done && !app.quit);
    app.interrupt();
    assert!(app.quit);
}

#[test]
fn quit_when_done_waits_while_a_password_is_asked_again() {
    let mut app = set_up(vec![Err(HostError::WrongPassword)]);
    app.begin(fix(vec![Call::Repair(Step::Packages)]), 0);
    app.quit_when_done = true;
    type_text(&mut app, "bad");
    app.key(Key::Enter);
    assert!(app.asking.is_some());
    app.tick(Instant::now());
    assert!(!app.quit, "the prompt is open");
}

#[test]
fn the_password_is_typed_on_a_legacy_screen_too() {
    let mut app = super::script_host::app(false, vec![]);
    app.open(super::app::Tab::Configuration);
    assert_eq!(app.nav.screen, super::nav::Screen::Legacy);
    app.begin(fix(vec![Call::Repair(Step::Packages)]), 0);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.host.calls.borrow()[0].1, "pw");
}

#[test]
fn grouped_work_reports_one_state_per_label() {
    let calls = |n: usize| vec![Call::Repair(Step::Packages); n];
    let work = Work::grouped(
        Kind::Ports {
            what: "Moving ports".into(),
            done: "Moved".into(),
        },
        vec![
            ("one".into(), calls(2)),
            ("two".into(), calls(2)),
            ("three".into(), calls(1)),
        ],
    );
    assert_eq!(work.labels[1], ("two".to_owned(), 2..4));
    let mut run = super::run::Run::new(work, Instant::now());
    for i in 0..3 {
        run.take(
            Progress {
                index: i,
                result: Ok("done\tok\n".into()),
            },
            Instant::now(),
        );
    }
    run.take(
        Progress {
            index: 3,
            result: Ok("failed\tdisk full\n".into()),
        },
        Instant::now(),
    );
    let states = super::run::label_states(&run);
    assert!(matches!(states[0], Some(StepState::Done(_))));
    assert_eq!(states[1], Some(StepState::Failed("disk full".into())));
    assert_eq!(states[2], None);
}

#[test]
fn a_finished_label_is_done_when_one_call_did_the_work() {
    let work = Work::grouped(
        Kind::Fix,
        vec![
            ("mixed".into(), vec![Call::Repair(Step::Packages); 2]),
            ("none".into(), vec![Call::Repair(Step::Packages); 2]),
        ],
    );
    let mut run = super::run::Run::new(work, Instant::now());
    for (i, line) in [
        "done\tdid it",
        "skipped\tnot chosen",
        "skipped\tfirst why",
        "skipped\tsecond why",
    ]
    .iter()
    .enumerate()
    {
        let result = Ok(format!("{line}\n"));
        run.take(Progress { index: i, result }, Instant::now());
    }
    let states = super::run::label_states(&run);
    assert_eq!(states[0], Some(StepState::Done("did it".into())));
    assert_eq!(states[1], Some(StepState::Skipped("first why".into())));
}
