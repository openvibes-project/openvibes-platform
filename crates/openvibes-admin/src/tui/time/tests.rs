//! System › Time, key by key.

use platform_host::timesync::TimeInfo;

use super::{At, TimePage};
use crate::tui::{
    app::{App, Key},
    nav::Screen,
    script_host::{SetupHost, body, screen, set_up, type_text},
};

fn info() -> TimeInfo {
    TimeInfo {
        zone: "Europe/Stockholm".into(),
        servers: vec!["ntp.lime.lab".into()],
        synced: Some(true),
    }
}

fn app_with(answers: Vec<Result<String, platform_host::HostError>>) -> App<SetupHost> {
    let app = set_up(answers);
    app.host.appliance.set(true);
    *app.host.time.borrow_mut() = Some(info());
    app
}

fn open(app: &mut App<SetupHost>) {
    app.open_system();
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Time);
}

fn password(app: &mut App<SetupHost>) {
    type_text(app, "pw");
    app.key(Key::Enter);
}

#[test]
fn system_lists_time_with_its_state() {
    let mut app = app_with(vec![]);
    app.open_system();
    let text = body(&app);
    assert!(
        text.contains("in sync · ntp.lime.lab · Europe/Stockholm"),
        "{text}"
    );
    let mut none = set_up(vec![]);
    none.host.appliance.set(true);
    none.open_system();
    assert!(!body(&none).contains("Time"));
}

#[test]
fn the_page_shows_the_settings_and_no_apply_until_something_differs() {
    let mut app = app_with(vec![]);
    open(&mut app);
    let text = screen(&app);
    assert!(
        text.contains("NTP servers") && text.contains("ntp.lime.lab"),
        "{text}"
    );
    assert_eq!(app.maint.time.rows(), [At::Servers, At::Zone]);
}

#[test]
fn a_bad_server_or_zone_is_said_and_kept_out() {
    let mut app = app_with(vec![]);
    open(&mut app);
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    type_text(&mut app, "bad host");
    assert!(screen(&app).contains("not a host name"));
    app.key(Key::Enter);
    assert!(app.maint.time.typing());
    app.key(Key::ClearLine);
    type_text(&mut app, "a.lab, 10.0.0.1");
    app.key(Key::Enter);
    assert!(!app.maint.time.typing());
    assert_eq!(app.maint.time.servers, "a.lab, 10.0.0.1");
    assert_eq!(app.maint.time.rows().last(), Some(&At::Apply));
    assert!(TimePage::note_for(At::Zone, "../etc").is_some_and(|n| n.is_err()));
}

#[test]
fn apply_runs_time_set() {
    let mut app = app_with(vec![Ok("done\tset\n".into())]);
    open(&mut app);
    app.key(Key::Down);
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    type_text(&mut app, "UTC");
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(screen(&app).contains("Change the time settings?"));
    app.key(Key::Enter);
    password(&mut app);
    let calls: Vec<String> = app
        .host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect();
    assert_eq!(calls, ["time-set --servers ntp.lime.lab --zone UTC"]);
}

#[test]
fn clearing_the_servers_is_a_change() {
    let mut app = app_with(vec![]);
    open(&mut app);
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    app.key(Key::Enter);
    assert!(app.maint.time.servers.is_empty());
    assert_eq!(app.maint.time.args().unwrap()[1], "");
    assert!(app.maint.time.rows().contains(&At::Apply));
}
