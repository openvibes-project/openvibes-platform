//! The list rows and the help line of Maintenance › Ports and addresses.

use platform_host::Host;
use ratatui::text::{Line, Span};

use super::ports::{PortRow, Ports, web};
use crate::tui::{app::App, ui::list::Row};

pub(super) fn row<H: Host>(app: &App<H>, ports: &Ports, at: usize) -> Row {
    let t = &app.theme;
    let (Some(was), Some(now)) = (&ports.saved, &ports.now) else {
        return Row::entry("", "");
    };
    if at == 3 {
        return Row::entry("Network devices", "514/udp");
    }
    if at == 4 {
        let says = if ports.agent_moved() {
            "agents must be told the new port"
        } else {
            "the web address changes"
        };
        return Row::entry("Apply", says);
    }
    let r = PortRow::ALL[at];
    let (old, new) = (r.of(was), r.of(now));
    let typed = app.nav.row == at && ports.typing.is_some();
    let dim = |s: String| vec![Span::styled(s, t.dim())];
    if let (true, Some(text)) = (typed, &ports.typing) {
        return Row::Entry {
            name: vec![Span::raw(r.name())],
            value: dim(format!("{text}█")),
        };
    }
    if ports.typing.is_some() {
        return Row::Entry {
            name: vec![Span::raw(r.name())],
            value: dim(new.to_string()),
        };
    }
    if !ports.moved().is_empty() && r == PortRow::Console && old == new {
        return Row::Entry {
            name: vec![Span::raw(r.name())],
            value: dim(new.to_string()),
        };
    }
    if old != new {
        return Row::Entry {
            name: vec![
                Span::styled("*", t.yellow()),
                Span::raw(format!(" {}", r.name())),
            ],
            value: dim(format!("{new} · was {old}")),
        };
    }
    let value = match r {
        PortRow::Console => format!("{new} · {}", web(&now.hostname, new)),
        _ => new.to_string(),
    };
    Row::Entry {
        name: vec![Span::raw(r.name())],
        value: dim(value),
    }
}

pub(super) fn help<H: Host>(app: &App<H>) -> Line<'static> {
    let t = &app.theme;
    let ports = &app.maint.ports;
    if ports.typing.is_some() {
        return match &ports.note {
            Some(Err(why)) => Line::styled(format!("    {why}"), t.red()),
            Some(Ok(ok)) => Line::styled(format!("    {ok}"), t.dim()),
            None => Line::raw(""),
        };
    }
    let text = match app.nav.row {
        0 => "The console's port; the web address follows it.".to_owned(),
        1 => "The port agents send their findings to.".into(),
        2 => "The port agents fetch their rules from.".into(),
        3 => "Network devices send their logs here; it is not changed on this page.".into(),
        _ if ports.agent_moved() => {
            "Agents on other hosts need their install line again after this.".into()
        }
        _ => format!("The console's web address changes to {}.", ports.address()),
    };
    Line::styled(format!("    {text}"), t.dim())
}
