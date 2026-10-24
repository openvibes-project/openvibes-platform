//! Maintenance › Certificates (certs2.py, certs4a.py): the server
//! certificates renew themselves, so the page says when next; the
//! intermediate, the previous one while agents move over, and the way to
//! the Names page and to Replace the intermediate. The dates and names are
//! read from the certificate files, not the plan.

use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use platform_host::{Host, HostError};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Page, info};
use crate::{
    setup::{
        pki::{RENEW_AT_DAYS, RENEW_DAYS},
        plan::{CaMode, plan_of},
        replace::{PREVIOUS, PREVIOUS_UNTIL, still_trusted},
    },
    tui::{
        app::{App, Key},
        run::Kind,
        status::wrap,
        ui::{
            bar::Bar,
            frame,
            list::{self, Row},
            logo::Header,
            theme::Theme,
        },
    },
};

const INGEST: &str = "/etc/openvibes/tls/ingest.crt";
/// The server certificates: renewed together, so the earliest is next.
const SERVER: [&str; 3] = [
    INGEST,
    "/etc/openvibes/tls/distribution.crt",
    "/etc/openvibes/tls/console-chain.pem",
];
const INTERMEDIATE: &str = "/etc/openvibes/pki/intermediate.crt";

type Pems<'a> = &'a [(&'a str, Result<String, HostError>)];

/// The report's rows, read when the page opens. Empty: no certificate yet.
#[derive(Debug, Default)]
pub struct Certs {
    rows: Vec<(&'static str, Vec<Span<'static>>)>,
    /// OpenVIBES made the CA: replacing needs the root key file.
    pub(super) quick: bool,
    /// Why Replace the intermediate did not open (ruling 7).
    refused: Option<String>,
}

fn pem_of<'a>(certs: Pems<'a>, path: &str) -> Option<&'a Result<String, HostError>> {
    certs.iter().find(|(p, _)| *p == path).map(|(_, pem)| pem)
}

/// The end of the certificate (a bundle's first).
fn until(pem: &str) -> Result<DateTime<Utc>, String> {
    platform_pki::not_after(pem).map_err(|e| format!("cannot be read ({e:?})"))
}

/// When the web and agent certificate ends (`YYYY-MM-DD`), if readable.
pub(super) fn valid_until<H: Host>(host: &H) -> Option<String> {
    let all = host.certificates();
    let Ok(pem) = pem_of(&all, INGEST)? else {
        return None;
    };
    Some(until(pem).ok()?.format("%Y-%m-%d").to_string())
}

/// The menu's one line: who signed the intermediate, and when the web
/// and agent certificate ends.
pub(super) fn summary<H: Host>(host: &H) -> String {
    summary_of(&host.certificates())
}

pub(super) fn summary_of(certs: Pems) -> String {
    let Some(leaf) = pem_of(certs, INGEST) else {
        return "no certificates yet".into();
    };
    let line = || -> Option<String> {
        let end = until(leaf.as_ref().ok()?).ok()?;
        let signer = pem_of(certs, INTERMEDIATE)?.as_ref().ok()?;
        let who = platform_pki::issuer_common_name(signer).ok()?;
        Some(format!(
            "signed by {} · until {}",
            who.unwrap_or_else(|| "an unnamed issuer".into()),
            end.format("%Y-%m-%d")
        ))
    };
    line().unwrap_or_else(|| "cannot be read".into())
}

/// When the previous intermediate stops being trusted; `None` when there
/// is none (both files are 0644, ruling 2).
pub(super) fn previous_until(root: &Path) -> Option<Result<String, String>> {
    if !root.join(PREVIOUS.trim_start_matches('/')).exists() {
        return None;
    }
    let text = std::fs::read_to_string(root.join(PREVIOUS_UNTIL.trim_start_matches('/')));
    Some(
        text.map_err(|e| e.to_string())
            .and_then(|t| DateTime::parse_from_rfc3339(t.trim()).map_err(|e| e.to_string()))
            .map(|until| until.format("%Y-%m-%d").to_string())
            .map_err(|e| format!("{PREVIOUS_UNTIL}: {e}")),
    )
}

/// "Web and agents": renewed automatically, and when next; red when the
/// renewal has not managed it with `RENEW_DAYS` left (Status says why).
fn renewal(
    t: &Theme,
    ends: Result<Vec<DateTime<Utc>>, String>,
    now: DateTime<Utc>,
) -> Vec<Span<'static>> {
    let end = match ends.map(|e| e.into_iter().min()) {
        Ok(Some(end)) => end,
        Ok(None) => return Vec::new(),
        Err(e) => return vec![Span::styled(e, t.red())],
    };
    if (end - now).num_days() < RENEW_DAYS {
        return vec![Span::styled("renewal is failing · see Status", t.red())];
    }
    let next = end - Duration::days(RENEW_AT_DAYS);
    let when = if next.date_naive() <= now.date_naive() {
        " · due today".to_owned()
    } else {
        format!(" · next {}", next.format("%Y-%m-%d"))
    };
    vec![
        Span::styled("renewed automatically", t.green()),
        Span::raw(when),
    ]
}

fn report(
    t: &Theme,
    certs: Pems,
    quick: bool,
    previous: Option<Result<String, String>>,
    now: DateTime<Utc>,
) -> Vec<(&'static str, Vec<Span<'static>>)> {
    let mut rows = Vec::new();
    let red = |e: String| vec![Span::styled(e, t.red())];
    let server: Vec<Result<DateTime<Utc>, String>> = SERVER
        .iter()
        .filter_map(|path| pem_of(certs, path))
        .map(|pem| {
            pem.as_ref()
                .map_err(ToString::to_string)
                .and_then(|p| until(p))
        })
        .collect();
    if !server.is_empty() {
        rows.push((
            "Web and agents",
            renewal(t, server.into_iter().collect(), now),
        ));
    }
    if let Some(pem) = pem_of(certs, INGEST) {
        let names = pem.as_ref().map_err(ToString::to_string).and_then(|p| {
            platform_pki::subject_alt_names(p)
                .map(|n| n.join(", "))
                .map_err(|e| format!("cannot be read ({e:?})"))
        });
        rows.push(("Names", names.map_or_else(red, |n| vec![Span::raw(n)])));
    }
    if let Some(pem) = pem_of(certs, INTERMEDIATE) {
        let signed = pem.as_ref().map_err(ToString::to_string).and_then(|p| {
            let who = platform_pki::issuer_common_name(p)
                .map_err(|e| format!("cannot be read ({e:?})"))?;
            Ok((who, until(p)?))
        });
        let value = match signed {
            Err(e) => red(e),
            Ok((who, end)) => {
                let end = format!(" · until {}", end.format("%Y-%m-%d"));
                let who = if quick {
                    Span::raw("the OpenVIBES root")
                } else {
                    Span::styled(who.unwrap_or_else(|| "an unnamed issuer".into()), t.bold())
                };
                vec![Span::raw("signed by "), who, Span::raw(end)]
            }
        };
        rows.push(("Intermediate", value));
        match previous {
            Some(Ok(date)) => {
                let text = format!("trusted until {date}, as agents move over");
                rows.push(("Previous intermediate", vec![Span::styled(text, t.dim())]));
            }
            Some(Err(e)) => rows.push(("Previous intermediate", red(e))),
            None => {}
        }
        if quick {
            let text = "offline: needed only to replace the intermediate";
            rows.push(("Root key", vec![Span::styled(text, t.dim())]));
        }
    }
    rows
}

const ACTIONS: [&str; 2] = ["Names", "Replace the intermediate"];

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let certs = &app.maint.certs;
    let row = app.nav.row.min(1);
    let bar = app.bar(Bar::keys(&[("Enter", ACTIONS[row])]));
    let area = frame::draw(frame, t, head, Some("Certificates"), &bar);
    let mut lines = vec![Line::raw("")];
    if certs.rows.is_empty() {
        lines.push(Line::styled(
            "    No certificates yet: run Repair.",
            t.dim(),
        ));
    }
    lines.extend(
        certs
            .rows
            .iter()
            .map(|(name, value)| info(name, value.clone())),
    );
    let replace = if certs.quick {
        "needs the offline root key file"
    } else {
        "a new request for your CA"
    };
    let rows = [
        Row::entry(ACTIONS[0], "add or remove a name agents use"),
        Row::entry(ACTIONS[1], replace),
    ];
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, row, &mut scroll, 5, 26));
    app.nav.scroll.set(scroll);
    if let Some(why) = &certs.refused {
        // In the list's last (blank) line, after one more when there is room.
        lines.pop();
        let said = wrap(why, 72, 2);
        if lines.len() + said.len() < usize::from(area.height) {
            lines.push(Line::raw(""));
        }
        lines.extend(
            said.into_iter()
                .map(|l| Line::styled(format!("    {l}"), t.red())),
        );
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Reads the certificate files again.
    pub(in crate::tui) fn read_certs(&mut self) {
        let quick = self
            .host
            .setup_plan()
            .ok()
            .and_then(|text| plan_of(&text).ok())
            .is_some_and(|plan| plan.ca == CaMode::Quick);
        let previous = previous_until(&self.root);
        let rows = report(
            &self.theme,
            &self.host.certificates(),
            quick,
            previous,
            Utc::now(),
        );
        self.maint.certs = Certs {
            rows,
            quick,
            refused: None,
        };
        // Back from a replacement that ended: on Names (certs4a.py #10).
        if self
            .run
            .as_ref()
            .is_some_and(|r| !r.running() && matches!(r.work.kind, Kind::Replace { .. }))
        {
            self.nav.row = 0;
        }
    }

    pub(super) fn open_certificates(&mut self) {
        self.nav.row = 0;
        self.read_certs();
    }

    pub(super) fn certificates_key(&mut self, key: Key) {
        if self.move_row(&key, ACTIONS.len()) || key != Key::Enter {
            return;
        }
        if self.nav.row == 0 {
            return self.open_page(Page::Names);
        }
        // Another replacement now would drop the intermediate most agents
        // still hold certificates from: the helper refuses it too.
        match previous_until(&self.root) {
            Some(Ok(date)) => self.maint.certs.refused = Some(still_trusted(&date)),
            Some(Err(why)) => self.maint.certs.refused = Some(why),
            None => self.open_page(Page::Replace),
        }
    }
}
