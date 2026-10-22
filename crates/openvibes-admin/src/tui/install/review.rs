//! Steps 4 and 5 of Choose what to install (advanced.py, full_advanced.py):
//! Ports, each checked as typed and a taken default moved with its reason
//! in yellow, and Review, every choice on one screen; Enter on a line goes
//! back to its step, Install asks for the password once.

use platform_host::Host;
use ratatui::{Frame, text::Span};

use super::{
    Ca, Install, fields,
    steps::{Step, draw_step, exists, tilde, typed},
};
use crate::{
    setup::plan::plan_of,
    tui::{
        app::App,
        maint::ports::{PortRow, port_note},
        ui::{bar::Bar, list::Row, logo::Header},
    },
};

const PORT_HELP: [&str; 5] = [
    "The console's port; the web address follows it.",
    "The port agents send their findings to.",
    "The port agents fetch their rules from.",
    "Network devices send their logs here; open it in your firewall.",
    "Go on to the review.",
];

impl Install {
    /// Row `row`'s port: the console, ingest, distribution.
    pub(super) fn port(&self, row: usize) -> &str {
        [
            &self.console_port,
            &self.ingest_port,
            &self.distribution_port,
        ][row]
    }

    /// What the line under Ports says of the port typed on `row`.
    pub(super) fn port_check<H: Host>(&self, host: &H, row: usize) -> Result<String, String> {
        let n = |row: usize| self.port(row).trim().parse::<u16>().unwrap_or(0);
        // The typed row counts as 0 in the plan: nothing is ours yet, so
        // every port is looked up.
        let ports: Vec<u16> = (0..3).map(|r| if r == row { 0 } else { n(r) }).collect();
        let plan = plan_of(&format!(
            "components = []\nhostname = \"\"\nca = \"quick\"\nconsole_port = {}\n\
             ingest_port = {}\ndistribution_port = {}\n",
            ports[0], ports[1], ports[2]
        ))?;
        let which = [PortRow::Console, PortRow::Ingest, PortRow::Distribution][row];
        port_note(host, &plan, which, self.port(row).trim())
    }

    /// Why Install cannot start yet: the names, the certificates, the root key.
    pub(super) fn not_ready(&self) -> Option<String> {
        if let Err(why) = fields::check_names(&self.hostname, &self.sans) {
            return Some(format!("✗ Names: {why}"));
        }
        match self.ca {
            Ca::Own if !self.accepted() => {
                Some("✗ Certificates: add both certificates first.".into())
            }
            Ca::Own => None,
            Ca::OpenVibes => fields::check_root_key(self.root_key_out.trim(), exists)
                .err()
                .map(|why| format!("✗ Root key file: {why}")),
        }
    }

    /// The helper kept both certificates of your own CA.
    pub(super) fn accepted(&self) -> bool {
        matches!(
            self.request,
            Some(crate::setup::request::RequestState::Signed { .. })
        )
    }
}

pub(super) fn draw_ports<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let install = &app.install;
    let row = app.nav.row;
    let names = ["Console", "Agent connections", "Rule distribution"];
    let mut rows: Vec<Row> = (0..3)
        .map(|r| {
            let port = install.port(r);
            let typing = install.editing.is_some() && row == r;
            let value = match (&install.proposed[r], typing) {
                (Some(why), false) => vec![
                    Span::styled(why.clone(), t.yellow()),
                    Span::styled(format!(" · {port} proposed"), t.dim()),
                ],
                _ => vec![Span::styled(typed(port, typing), t.dim())],
            };
            Row::Entry {
                name: vec![Span::raw(names[r])],
                value,
            }
        })
        .collect();
    rows.push(Row::entry(
        "Network devices",
        "514/udp · open it in your firewall",
    ));
    rows.push(Row::entry("Next", "review"));
    let (help, red) = match (&install.port_check, row) {
        (Some(Err(why)), _) if install.editing.is_some() => (why.clone(), true),
        (Some(Ok(ok)), _) if install.editing.is_some() => (ok.clone(), false),
        (_, r) if r < 3 && install.proposed[r].is_some() => (
            format!("Enter to keep {} or type another port.", install.port(r)),
            false,
        ),
        _ => (PORT_HELP[row.min(4)].to_owned(), false),
    };
    let bar = match (install.editing.is_some(), row) {
        (true, _) => Bar::edit(names[row.min(2)], "type a port", &[("Enter", "Done")]),
        (_, 4) => Bar::keys(&[("Enter", "Next")]),
        (_, 3) => Bar::keys(&[]),
        _ => Bar::keys(&[("Enter", "Change")]),
    };
    let step = Step {
        at: 3,
        rows,
        help: &help,
        red,
        bar,
        width: 22,
    };
    draw_step(frame, head, app, step);
}

pub(super) fn draw_review<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let install = &app.install;
    let row = app.nav.row;
    let optional = [
        if install.agent {
            "agent on this host"
        } else {
            "no agent on this host"
        },
        if install.assistant {
            "assistant"
        } else {
            "no assistant"
        },
    ]
    .join(" · ");
    let names: Vec<&str> = std::iter::once(install.hostname.trim())
        .chain(install.sans.split(',').map(str::trim))
        .filter(|s| !s.is_empty())
        .collect();
    let certs = match (install.ca, &install.signed) {
        (Ca::Own, Some(who)) if install.accepted() => vec![
            Span::styled("your own CA · ", t.dim()),
            Span::styled(format!("✓ signed by {who}"), t.green()),
        ],
        (Ca::Own, _) => vec![
            Span::styled("your own CA · ", t.dim()),
            Span::styled("not added yet", t.yellow()),
        ],
        (Ca::OpenVibes, _) => vec![Span::styled(
            format!(
                "OpenVIBES makes one · {}",
                tilde(install.root_key_out.trim(), install.home.as_deref())
            ),
            t.dim(),
        )],
    };
    let ports = format!(
        "{}, {}, {}, 514/udp",
        install.console_port, install.ingest_port, install.distribution_port
    );
    let rows = vec![
        Row::entry("Optional", &optional),
        Row::entry("Names", &names.join(", ")),
        Row::Entry {
            name: vec![Span::raw("Certificates")],
            value: certs,
        },
        Row::entry("Ports", &ports),
        Row::entry("Install", "asks for your password once"),
    ];
    let refused = (row == 4).then(|| install.not_ready()).flatten();
    let help = match &refused {
        Some(why) => why.as_str(),
        None if row == 4 => "Starts the install; it asks for your password once.",
        None => "Enter goes back to this step to change it.",
    };
    let bar = if row == 4 {
        Bar::keys(&[("Enter", "Install")])
    } else {
        Bar::keys(&[("Enter", "Change")])
    };
    let step = Step {
        at: 4,
        rows,
        help,
        red: refused.is_some(),
        bar,
        width: 22,
    };
    draw_step(frame, head, app, step);
}
