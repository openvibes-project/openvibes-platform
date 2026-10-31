//! System › Network, key by key (system.py).

use std::time::{Duration, Instant};

use platform_host::network::{Method, NetInfo};

use super::At;
use crate::tui::{
    app::{App, Key},
    nav::Screen,
    script_host::{SetupHost, body, screen, set_up, type_text},
};

fn info() -> NetInfo {
    NetInfo {
        connection: "Wired connection 1".into(),
        uuid: "5d1f3a7c-1111-4222-8333-944455556666".into(),
        device: "eth0".into(),
        method: Some(Method::Dhcp),
        dns_auto: true,
        now_address: "192.168.1.50/24".into(),
        now_gateway: "192.168.1.1".into(),
        now_dns: vec!["192.168.1.1".into()],
        now_search: "lime.lab".into(),
        hostname: "openvibes-va.lime.lab".into(),
        ..NetInfo::default()
    }
}

fn app_with(answers: Vec<Result<String, platform_host::HostError>>) -> App<SetupHost> {
    let app = set_up(answers);
    app.host.appliance.set(true);
    *app.host.net.borrow_mut() = Some(info());
    app
}

fn open(app: &mut App<SetupHost>) {
    app.open_system();
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Network);
}

fn calls(app: &App<SetupHost>) -> Vec<String> {
    app.host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect()
}

fn password(app: &mut App<SetupHost>) {
    type_text(app, "pw");
    app.key(Key::Enter);
}

fn down(app: &mut App<SetupHost>, n: usize) {
    for _ in 0..n {
        app.key(Key::Down);
    }
}

fn row_of(app: &App<SetupHost>, at: At) -> usize {
    app.maint.net.rows().iter().position(|r| *r == at).unwrap()
}

#[test]
fn system_lists_network_first_only_where_networkmanager_has_a_connection() {
    let mut app = app_with(vec![]);
    app.open_system();
    let text = body(&app);
    assert!(
        text.contains("Network") && text.contains("192.168.1.50 · DHCP · eth0"),
        "{text}"
    );
    let mut plain = set_up(vec![]);
    plain.host.appliance.set(true);
    plain.open_system();
    assert!(!body(&plain).contains("Network"));
}

#[test]
fn the_page_shows_now_and_the_choices() {
    let mut app = app_with(vec![]);
    open(&mut app);
    let text = screen(&app);
    assert!(
        text.contains("eth0 · 192.168.1.50/24 · gateway 192.168.1.1 · DNS 192.168.1.1"),
        "{text}"
    );
    assert!(
        text.contains("(•) DHCP") && text.contains("( ) Fixed address"),
        "{text}"
    );
    assert!(text.contains("[x] Use the DNS from DHCP"), "{text}");
    assert!(!app.maint.net.rows().contains(&At::Apply));
    assert!(app.maint.net.rows().contains(&At::Host));
}

#[test]
fn fixed_address_starts_from_what_dhcp_gave() {
    let mut app = app_with(vec![]);
    open(&mut app);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    let text = screen(&app);
    assert!(text.contains("(•) Fixed address"), "{text}");
    let net = &app.maint.net;
    assert_eq!(
        (net.address.as_str(), net.gateway.as_str(), net.dns.as_str()),
        ("192.168.1.50/24", "192.168.1.1", "192.168.1.1")
    );
    assert!(net.rows().contains(&At::Apply));
}

#[test]
fn a_bad_value_is_said_in_red_and_kept_out() {
    let mut app = app_with(vec![]);
    open(&mut app);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    down(&mut app, 1);
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    type_text(&mut app, "192.168.1.50");
    assert!(screen(&app).contains("ADDRESS/PREFIX"));
    app.key(Key::Enter);
    assert!(app.maint.net.typing());
    assert_eq!(app.maint.net.address, "192.168.1.50/24");
    type_text(&mut app, "/24");
    app.key(Key::Enter);
    assert!(!app.maint.net.typing());
}

#[test]
fn a_gateway_off_the_network_is_refused_as_typed() {
    let mut app = app_with(vec![]);
    open(&mut app);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    down(&mut app, 2);
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    type_text(&mut app, "10.0.0.1");
    assert!(screen(&app).contains("Not on the same network"));
}

#[test]
fn a_dns_server_that_does_not_answer_stops_apply() {
    let mut app = app_with(vec![]);
    *app.host.silent.borrow_mut() = vec!["9.9.9.9".into()];
    open(&mut app);
    app.maint.net.own_dns = true;
    app.maint.net.dns = "9.9.9.9".into();
    let apply = row_of(&app, At::Apply);
    down(&mut app, apply);
    app.key(Key::Enter);
    assert!(app.question.is_none());
    assert!(screen(&app).contains("9.9.9.9 does not answer"));
}

#[test]
fn apply_runs_net_apply_then_offers_keep_or_put_back() {
    let mut app = app_with(vec![Ok("done\tpending\t60\n".into())]);
    open(&mut app);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    let apply = row_of(&app, At::Apply);
    down(&mut app, apply - 1);
    app.key(Key::Enter);
    assert!(screen(&app).contains("Apply the network settings?"));
    app.key(Key::Enter);
    password(&mut app);
    assert_eq!(
        calls(&app),
        [
            "net-apply --mode fixed --address 192.168.1.50/24 --gateway 192.168.1.1 --dns 192.168.1.1 --search lime.lab"
        ]
    );
    let text = screen(&app);
    assert!(text.contains("The new settings are in use."), "{text}");
    assert!(
        text.contains("Keep these settings") && text.contains("Put the old ones back"),
        "{text}"
    );
    assert!(app.maint.net.keep.is_some());
}

#[test]
fn keep_runs_net_keep_and_says_so() {
    let mut app = app_with(vec![Ok("done\tkept\n".into())]);
    open(&mut app);
    app.maint.net.keep = Some(Instant::now());
    app.key(Key::Enter);
    password(&mut app);
    assert_eq!(calls(&app), ["net-keep"]);
    assert!(app.maint.net.keep.is_none());
    assert!(screen(&app).contains("The new settings are kept."));
}

#[test]
fn put_back_runs_net_revert() {
    let mut app = app_with(vec![Ok("done\treverted\n".into())]);
    open(&mut app);
    app.maint.net.keep = Some(Instant::now());
    app.key(Key::Down);
    app.key(Key::Enter);
    password(&mut app);
    assert_eq!(calls(&app), ["net-revert"]);
    assert!(screen(&app).contains("The old settings are back."));
}

#[test]
fn a_lapsed_minute_reads_the_host_again_and_says_so() {
    let mut app = app_with(vec![]);
    open(&mut app);
    app.maint.net.keep = Instant::now().checked_sub(Duration::from_secs(75));
    app.tick(Instant::now());
    assert!(app.maint.net.keep.is_none());
    assert!(screen(&app).contains("Nobody answered, so the old settings are back."));
}

#[test]
fn only_the_host_name_runs_hostname_set() {
    let mut app = app_with(vec![Ok("done\tva.lab\n".into())]);
    open(&mut app);
    let host = row_of(&app, At::Host);
    down(&mut app, host);
    app.key(Key::Enter);
    app.key(Key::ClearLine);
    type_text(&mut app, "va.lab");
    app.key(Key::Enter);
    let apply = row_of(&app, At::Apply);
    down(&mut app, apply - host);
    app.key(Key::Enter);
    assert!(screen(&app).contains("Change the host name?"));
    app.key(Key::Enter);
    password(&mut app);
    assert_eq!(calls(&app), ["hostname-set va.lab"]);
    assert!(app.maint.net.keep.is_none());
}
