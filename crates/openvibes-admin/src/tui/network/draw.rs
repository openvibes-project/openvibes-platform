//! The Network page's screens: the list, the keep-or-put-back question and
//! a run's progress or failure.

use platform_host::{Host, StepState, network::Method};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{At, Net};
use crate::tui::{
    app::App,
    kind::{Kind, NetAction},
    maint::failure,
    run::Run,
    status::wrap,
    ui::{
        bar::{Bar, SPINNER},
        frame,
        list::{self, Row},
        logo::Header,
    },
};

pub(super) fn net_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Net(_)))
}

fn radio(on: bool) -> &'static str {
    if on { "(•) " } else { "( ) " }
}

fn row<H: Host>(app: &App<H>, net: &Net, at: At, selected: bool) -> Row {
    let t = &app.theme;
    let typed = net.typing.as_ref().filter(|_| selected);
    let dim = |s: String| vec![Span::styled(s, t.dim())];
    let plain = |name: &str, value: String| Row::Entry {
        name: vec![Span::raw(name.to_owned())],
        value: dim(value),
    };
    let field = |name: &str, shown: &str| match typed {
        Some(text) => plain(name, format!("{text}█")),
        None if shown.is_empty() => plain(name, "not set".into()),
        None => plain(name, shown.to_owned()),
    };
    let mode = net.mode;
    match at {
        At::Dhcp => plain(
            &format!("{}DHCP", radio(mode == Some(Method::Dhcp))),
            "address from your network".into(),
        ),
        At::Fixed => plain(
            &format!("{}Fixed address", radio(mode == Some(Method::Fixed))),
            "you type it below".into(),
        ),
        At::Address => field("Address", &net.address),
        At::Gateway => field("Gateway", &net.gateway),
        At::DnsAuto => {
            let mark = if net.own_dns { "[ ]" } else { "[x]" };
            let dns = net
                .info
                .as_ref()
                .map(|i| i.now_dns.join(", "))
                .unwrap_or_default();
            Row::Entry {
                name: vec![
                    Span::styled(mark, if net.own_dns { t.dim() } else { t.green() }),
                    Span::raw(" Use the DNS from DHCP"),
                ],
                value: dim(dns),
            }
        }
        At::Dns => field("DNS servers", &net.dns_text()),
        At::Search => field("Search domain", &net.search),
        At::Host => field("Host name", &net.host),
        At::Apply => plain("Apply", apply_says(net)),
        At::Keep => plain("Keep these settings", "the new address stays".into()),
        At::Revert => plain("Put the old ones back", "now".into()),
    }
}

fn apply_says(net: &Net) -> String {
    match (net.net_changed(), net.host_changed()) {
        (true, true) => "network settings and host name".into(),
        (true, false) => "checked first; undone in a minute unless kept".into(),
        (false, _) => "the host name".into(),
    }
}

/// What the line(s) under the list say.
fn help<H: Host>(app: &App<H>, net: &Net, at: Option<At>) -> Vec<Line<'static>> {
    let t = &app.theme;
    if net.typing.is_some() {
        return vec![match &net.note {
            Some(Err(why)) => Line::styled(format!("    {why}"), t.red()),
            Some(Ok(ok)) => Line::styled(format!("    {ok}"), t.dim()),
            None => Line::raw(""),
        }];
    }
    if let Some(said) = &net.said {
        return match said {
            Ok(text) => vec![Line::styled(format!("    ✓ {text}"), t.green())],
            Err(text) => wrap(text, 72, 2)
                .into_iter()
                .map(|l| Line::styled(format!("    {l}"), t.yellow()))
                .collect(),
        };
    }
    let text = match at {
        Some(At::Dhcp) => "The address, gateway and DNS come from your network.".to_owned(),
        Some(At::Fixed) => "The fields start from what DHCP gave.".into(),
        Some(At::Dns | At::DnsAuto) => {
            "Name servers this appliance asks; agents and feeds need them.".into()
        }
        Some(At::Host) => "The name this host is known by.".into(),
        Some(At::Apply) => {
            if net.net_changed() {
                "Agents that use the old address need their install line again.".into()
            } else {
                "Agents that use the old name stop connecting: they need the new install line."
                    .into()
            }
        }
        Some(At::Keep | At::Revert) => {
            "If nobody answers, the old settings come back by themselves.".into()
        }
        _ => String::new(),
    };
    wrap(&text, 72, 2)
        .into_iter()
        .map(|l| Line::styled(format!("    {l}"), t.dim()))
        .collect()
}

fn header<H: Host>(app: &App<H>, net: &Net) -> Vec<Line<'static>> {
    let t = &app.theme;
    let Some(info) = &net.info else {
        return Vec::new();
    };
    let mut now = Vec::new();
    if !info.now_address.is_empty() {
        now.push(info.now_address.clone());
    }
    if !info.now_gateway.is_empty() {
        now.push(format!("gateway {}", info.now_gateway));
    }
    if !info.now_dns.is_empty() {
        now.push(format!("DNS {}", info.now_dns.join(", ")));
    }
    vec![Line::styled(
        format!("    {} · {}", info.device, now.join(" · ")),
        t.dim(),
    )]
}

fn draw_run<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let mut lines = vec![Line::raw("")];
    let bar = if run.running() {
        let spin = SPINNER[app.tick_count % SPINNER.len()];
        lines.push(Line::from(vec![
            Span::styled(format!("    {spin} "), t.teal()),
            Span::raw(format!("{}…", run.work.kind.doing())),
        ]));
        Bar::Busy {
            text: run.work.kind.doing(),
            tick: app.tick_count,
        }
    } else if run.ok() {
        lines.push(Line::styled(
            format!("    ✓ {}{}", run.work.kind.done(), run.took()),
            t.green(),
        ));
        Bar::keys(&[("Enter", "Back")])
    } else {
        let at = run.stopped_at().unwrap_or(0);
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        let todo = match run.work.kind {
            Kind::Net(NetAction::Apply { .. }) => {
                "The old settings are back. Try again runs it once more."
            }
            _ => "Try again runs it once more.",
        };
        lines.extend(failure(t, why, todo));
        Bar::act(&[("Enter", "Try again")])
    };
    let area = frame::draw(frame, t, head, Some("Network"), &app.bar(bar));
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = net_run(app) {
        return draw_run(frame, head, app, run);
    }
    let t = &app.theme;
    let net = &app.maint.net;
    if net.info.is_none() {
        let area = frame::draw(frame, t, head, Some("Network"), &app.bar(Bar::act(&[])));
        let lines = failure(
            t,
            "There is no wired connection under NetworkManager to manage.",
            "",
        );
        return frame.render_widget(Paragraph::new(lines), area);
    }
    let rows = net.rows();
    let at = rows.get(app.nav.row).copied();
    let bar = if net.typing.is_some() {
        let label = match at {
            Some(At::Address) => "Address",
            Some(At::Gateway) => "Gateway",
            Some(At::Dns) => "DNS servers",
            Some(At::Search) => "Search domain",
            _ => "Host name",
        };
        Bar::edit(label, "type a value", &[("Enter", "Done")])
    } else {
        match at {
            Some(At::Dhcp | At::Fixed) => Bar::keys(&[("Space", "Choose")]),
            Some(At::DnsAuto) => Bar::keys(&[("Space", "Select/deselect")]),
            Some(At::Apply) => Bar::keys(&[("Enter", "Apply")]),
            Some(At::Keep) => Bar::keys(&[("Enter", "Keep")]),
            Some(At::Revert) => Bar::keys(&[("Enter", "Put back")]),
            _ => Bar::keys(&[("Enter", "Change")]),
        }
    };
    let area = frame::draw(frame, t, head, Some("Network"), &app.bar(bar));
    let mut lines = Vec::new();
    if net.keep.is_some() {
        lines.push(Line::from(vec![
            Span::styled("    ▲ ", t.yellow()),
            Span::raw("The new settings are in use."),
        ]));
        lines.push(Line::styled(
            if net.lapsed {
                "    The old ones did not come back by themselves.".to_owned()
            } else {
                format!(
                    "    Keep them? The old ones come back in {} s.",
                    net.seconds_left()
                )
            },
            t.dim(),
        ));
        lines.push(Line::raw(""));
    } else {
        lines.extend(header(app, net));
    }
    let help = help(app, net, at);
    let list_rows: Vec<Row> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| row(app, net, *r, i == app.nav.row))
        .collect();
    let height = area
        .height
        .saturating_sub(u16::try_from(lines.len() + help.len()).unwrap_or(u16::MAX));
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(
        t,
        &list_rows,
        app.nav.row,
        &mut scroll,
        height,
        30,
    ));
    app.nav.scroll.set(scroll);
    lines.extend(help);
    frame.render_widget(Paragraph::new(lines), area);
}
