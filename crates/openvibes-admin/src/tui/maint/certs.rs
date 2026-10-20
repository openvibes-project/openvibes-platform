//! Maintenance › Certificates (maint2b.py #18): a report of the server
//! certificate and the intermediate, and the way to the Names page. The
//! dates and names are read from the certificate files, not the plan.

use chrono::{DateTime, Utc};
use platform_host::{Host, HostError};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Page, info};
use crate::{
    setup::plan::{CaMode, plan_of},
    tui::{
        app::{App, Key},
        ui::{
            bar::Bar,
            frame,
            list::{self, Row},
            logo::Header,
        },
    },
};

const INGEST: &str = "/etc/openvibes/tls/ingest.crt";
const INTERMEDIATE: &str = "/etc/openvibes/pki/intermediate.crt";

type Pems<'a> = &'a [(&'a str, Result<String, HostError>)];

/// The report's rows: (name, value, red). Empty: no certificate yet.
#[derive(Debug, Default)]
pub struct Certs {
    rows: Vec<(&'static str, String, bool)>,
}

fn pem_of<'a>(certs: Pems<'a>, path: &str) -> Option<&'a Result<String, HostError>> {
    certs.iter().find(|(p, _)| *p == path).map(|(_, pem)| pem)
}

/// The end of the certificate.
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

/// The menu's one line: who signed the intermediate and until when.
pub(super) fn summary<H: Host>(host: &H) -> String {
    let all = host.certificates();
    let Some(Ok(pem)) = pem_of(&all, INTERMEDIATE) else {
        return "no certificates yet".into();
    };
    match (platform_pki::issuer_common_name(pem), until(pem)) {
        (Ok(who), Ok(end)) => format!(
            "signed by {} · until {}",
            who.unwrap_or_else(|| "an unnamed issuer".into()),
            end.format("%Y-%m-%d")
        ),
        _ => "cannot be read".into(),
    }
}

fn report(certs: Pems, quick: bool, now: DateTime<Utc>) -> Certs {
    let mut rows = Vec::new();
    let mut web = |name, value: Result<String, String>| match value {
        Ok(v) => rows.push((name, v, false)),
        Err(e) => rows.push((name, e, true)),
    };
    if let Some(pem) = pem_of(certs, INGEST) {
        let pem = pem.as_ref().map_err(ToString::to_string);
        let valid = pem.clone().and_then(|p| until(p)).and_then(|end| {
            let date = end.format("%Y-%m-%d");
            let days = (end.date_naive() - now.date_naive()).num_days();
            if end <= now {
                Err(format!("expired {date}"))
            } else if days == 1 {
                Ok(format!("valid until {date} · 1 day left"))
            } else {
                Ok(format!("valid until {date} · {days} days left"))
            }
        });
        web("Web and agents", valid);
        let names = pem.and_then(|p| {
            platform_pki::subject_alt_names(p)
                .map(|n| n.join(", "))
                .map_err(|e| format!("cannot be read ({e:?})"))
        });
        web("Names", names);
    }
    if let Some(pem) = pem_of(certs, INTERMEDIATE) {
        let signed = pem
            .as_ref()
            .map_err(ToString::to_string)
            .and_then(|p| {
                let who = platform_pki::issuer_common_name(p)
                    .map_err(|e| format!("cannot be read ({e:?})"))?;
                Ok((who, until(p)?))
            })
            .map(|(who, end)| {
                let who = who.unwrap_or_else(|| "an unnamed issuer".into());
                format!("signed by {who} · until {}", end.format("%Y-%m-%d"))
            });
        web("Intermediate", signed);
        if quick {
            web(
                "Root key",
                Ok("offline: needed only to replace the intermediate".into()),
            );
        }
    }
    Certs { rows }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let bar = app.bar(Bar::keys(&[("Enter", "Names")]));
    let area = frame::draw(frame, t, head, Some("Certificates"), &bar);
    let mut lines = vec![Line::raw("")];
    if app.maint.certs.rows.is_empty() {
        lines.push(Line::styled(
            "    No certificates yet: run Repair.",
            t.dim(),
        ));
    }
    for (name, value, red) in &app.maint.certs.rows {
        let value = if *red {
            Span::styled(value.clone(), t.red())
        } else {
            Span::raw(value.clone())
        };
        lines.push(info(name, vec![value]));
    }
    let rows = [Row::entry("Names", "add or remove a name agents use")];
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, 0, &mut scroll, 3, 26));
    app.nav.scroll.set(scroll);
    lines.push(Line::styled(
        "    Names agents and browsers may use to reach this host.",
        t.dim(),
    ));
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Reads the certificate files again.
    pub(super) fn read_certs(&mut self) {
        let quick = self
            .host
            .setup_plan()
            .ok()
            .and_then(|text| plan_of(&text).ok())
            .is_some_and(|plan| plan.ca == CaMode::Quick);
        self.maint.certs = report(&self.host.certificates(), quick, Utc::now());
    }

    pub(super) fn open_certificates(&mut self) {
        self.nav.row = 0;
        self.read_certs();
    }

    pub(super) fn certificates_key(&mut self, key: Key) {
        if key == Key::Enter {
            self.open_page(Page::Names);
        }
    }
}
