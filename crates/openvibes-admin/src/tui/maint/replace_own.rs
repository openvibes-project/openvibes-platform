//! Replace with your own CA (certs4a.py #2-9): the install's request rows,
//! the CAs kept from this host (`root.crt`, then `chain.crt`) unless they
//! are added again, then Replace.

use platform_host::Host;
use ratatui::text::Span;

use super::{import::Layout, owned};
use crate::tui::{app::App, ui::list::Row};

pub(super) fn page<H: Host>(app: &App<H>) -> Layout {
    let (t, row, install, replace) = (&app.theme, app.nav.row, &app.install, &app.maint.replace);
    let root = replace
        .root
        .as_ref()
        .map(|r| r.as_ref().map(|(_, name)| name));
    let signed = match &install.signed {
        Some(who) => vec![
            Span::styled("✓ added", t.green()),
            Span::styled(format!(" · signed by {who}"), t.dim()),
        ],
        None => vec![Span::styled("not added yet", t.yellow())],
    };
    let kept = match root {
        _ if replace.readded => match &install.root_added {
            Some(name) => vec![
                Span::styled("✓ added", t.green()),
                Span::styled(format!(" · {name}"), t.dim()),
            ],
            None => vec![Span::styled("not added yet", t.yellow())],
        },
        Some(Ok(name)) => vec![
            Span::styled("✓", t.green()),
            Span::raw(format!(" {name} (kept)")),
        ],
        _ => vec![Span::styled("cannot be read", t.red())],
    };
    let ready = install.accepted();
    let rows = vec![
        Row::entry("Show the request", "to copy it to your CA"),
        Row::Entry {
            name: vec![Span::raw("Signed certificate")],
            value: signed,
        },
        Row::Entry {
            name: vec![Span::raw("Your CA's certificate")],
            value: kept,
        },
        Row::entry(
            "Replace",
            if ready {
                "a new intermediate from your CA"
            } else {
                "once the signed certificate is added"
            },
        ),
    ];
    let enter = match row {
        0 => Some("Show the request"),
        1 => Some("Add the signed certificate"),
        2 => Some("Add your CA's certificate"),
        3 if ready => Some("Replace"),
        _ => None,
    };
    let said = match (&install.error, root) {
        (Some(why), _) => Some(Err(why.as_str())),
        (None, Some(Err(why))) => Some(Err(why.as_str())),
        _ => None,
    };
    let note = "The same steps as at install. Nothing changes until Replace.";
    (note, rows, enter, owned(said))
}
