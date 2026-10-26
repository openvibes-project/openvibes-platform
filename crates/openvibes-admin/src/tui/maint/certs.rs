//! Maintenance › Certificates (certs2.py, certs4a.py, certs4b.py #10,
//! certs4c.py #1, #9, #13): the server certificates renew themselves, so
//! the page says when next; the console's (the platform's, or your own and
//! when it ends); the intermediate (an imported one: from your PKI, and the
//! CAs above it), the previous one while agents move over, and the way to
//! the Names page, to Replace the intermediate and to the Console
//! certificate. The dates and names are read from the certificate files,
//! not the plan; how the CA was made is the plan's.

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
        pki::{RENEW_AT_DAYS, RENEW_DAYS, ROOT_CERT},
        pki_import::{CHAIN, lost},
        plan::{CaMode, plan_of},
        replace::{PREVIOUS, PREVIOUS_UNTIL, still_trusted},
    },
    tui::{
        app::{App, Key},
        console_cert_check::{WARN_DAYS, days_left},
        install::server_check::name_of,
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
    /// How the CA was made; `None` when the plan cannot be read.
    pub(super) ca: Option<CaMode>,
    /// Why Replace the intermediate did not open (ruling 7).
    refused: Option<String>,
    /// Your own console certificate (its PEM), if the console uses one.
    pub(super) own: Option<String>,
}

impl Certs {
    /// OpenVIBES made the CA: replacing needs the root key file.
    pub(super) fn quick(&self) -> bool {
        self.ca == Some(CaMode::Quick)
    }

    /// Imported from your PKI: Replace imports the next one.
    pub(super) fn imported(&self) -> bool {
        self.ca == Some(CaMode::Import)
    }
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

/// "Agents": renewed automatically, and when next; red when the
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

/// "Console": the platform's, renewed with the agents; or your own, amber
/// within `WARN_DAYS` of its end and red once ended.
pub(super) fn console_row(t: &Theme, own: Option<&str>, now: DateTime<Utc>) -> Vec<Span<'static>> {
    let Some(pem) = own else {
        return vec![
            Span::styled("from the platform", t.green()),
            Span::raw(" · renewed with the agents"),
        ];
    };
    let Ok(end) = until(pem) else {
        return vec![Span::styled("your own · cannot be read", t.red())];
    };
    let date = end.format("%Y-%m-%d");
    if end <= now {
        return vec![Span::styled(format!("your own · ended on {date}"), t.red())];
    }
    let days = (end - now).num_days();
    if days <= WARN_DAYS {
        let text = format!("your own · ends {date}, {}", days_left(days));
        return vec![Span::styled(text, t.yellow())];
    }
    let name = name_of(pem).map(|n| format!(" · {n}")).unwrap_or_default();
    vec![
        Span::styled("your own", t.bold()),
        Span::raw(format!("{name} · until {date}")),
    ]
}

/// Said for Signed by when `ours` is under a sub-CA and `CHAIN` is gone.
const LOST: &str = "chain.crt is missing";

/// The common names above our intermediate, root last: `CHAIN`'s CAs
/// (none for a two-level PKI), then the root (both 0644); `LOST` when
/// `CHAIN` is gone and the root did not sign `ours` itself.
fn signed_by(root: &Path, ours: Option<&str>) -> Result<Vec<String>, String> {
    let read = |abs: &str| std::fs::read_to_string(root.join(abs.trim_start_matches('/')));
    let root = read(ROOT_CERT).map_err(|e| format!("{ROOT_CERT}: {e}"))?;
    let chain = match read(CHAIN) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if ours.is_some_and(|ours| lost(ours, &root).is_some()) {
                return Err(LOST.into());
            }
            String::new()
        }
        text => text.map_err(|e| format!("{CHAIN}: {e}"))?,
    };
    let pems = format!("{chain}\n{root}");
    pems.split_inclusive("-----END CERTIFICATE-----")
        .filter(|pem| pem.contains("-----BEGIN CERTIFICATE-----"))
        .map(|pem| platform_pki::common_name(pem).map_err(|e| format!("cannot be read ({e:?})")))
        .collect()
}

fn report(
    t: &Theme,
    certs: Pems,
    own: Option<&str>,
    ca: Option<CaMode>,
    above: Option<Result<Vec<String>, String>>,
    previous: Option<Result<String, String>>,
    now: DateTime<Utc>,
) -> Vec<(&'static str, Vec<Span<'static>>)> {
    let quick = ca == Some(CaMode::Quick);
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
        rows.push(("Agents", renewal(t, server.into_iter().collect(), now)));
        rows.push(("Console", console_row(t, own, now)));
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
            Ok((_, end)) if ca == Some(CaMode::Import) => {
                vec![Span::raw(format!(
                    "from your PKI · until {}",
                    end.format("%Y-%m-%d")
                ))]
            }
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
        match above {
            Some(Ok(names)) => {
                let mut spans = Vec::new();
                for (i, name) in names.iter().enumerate() {
                    if i + 1 == names.len() {
                        spans.push(Span::styled(name.clone(), t.bold()));
                    } else {
                        spans.push(Span::raw(format!("{name} › ")));
                    }
                }
                rows.push(("Signed by", spans));
            }
            Some(Err(e)) => rows.push(("Signed by", red(e))),
            None => {}
        }
        match previous {
            Some(Ok(date)) => {
                let text = format!("trusted until {date}, as agents move over");
                rows.push(("Previous intermediate", vec![Span::styled(text, t.dim())]));
            }
            Some(Err(e)) => rows.push(("Previous intermediate", red(e))),
            None => {}
        }
    }
    rows
}

const ACTIONS: [&str; 3] = ["Names", "Replace the intermediate", "Console certificate"];

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let certs = &app.maint.certs;
    let row = app.nav.row.min(2);
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
    let replace = match certs.ca {
        Some(CaMode::Quick) => "needs the offline root key file",
        Some(CaMode::Import) => "import the next one from your PKI",
        _ => "a new request for your CA",
    };
    let console = if certs.own.is_some() {
        "use a new one, or go back to the platform's"
    } else {
        "use your own"
    };
    let rows = [
        Row::entry(ACTIONS[0], "add or remove a name agents use"),
        Row::entry(ACTIONS[1], replace),
        Row::entry(ACTIONS[2], console),
    ];
    let said = (certs.refused.as_deref()).map_or_else(Vec::new, |why| wrap(why, 72, 2));
    // The three entries, a blank line above and below. Its last blank line
    // may fall off the screen; with less room the list scrolls. A refusal
    // takes that last line and the lines below.
    let full = 7;
    let used = lines.len() + said.len().saturating_sub(1);
    let room = usize::from(area.height).saturating_sub(used);
    let height = if room + 1 >= full { full } else { room.max(3) };
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, row, &mut scroll, height as u16, 26));
    app.nav.scroll.set(scroll);
    if !said.is_empty() {
        // After one more blank line when there is room.
        lines.pop();
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
        let ca = self
            .host
            .setup_plan()
            .ok()
            .and_then(|text| plan_of(&text).ok())
            .map(|plan| plan.ca);
        let mut certs = self.host.certificates();
        // The console's file holds your own certificate then: it is not
        // renewed with the agents'.
        let own = self.host.own_console_cert();
        if own.is_some() {
            certs.retain(|(path, _)| *path != SERVER[2]);
        }
        let ours = pem_of(&certs, INTERMEDIATE).and_then(|pem| pem.as_ref().ok());
        let chained = self.root.join(CHAIN.trim_start_matches('/')).exists();
        // Always for an import; otherwise with CAs between ours and the
        // root, or when they are lost: right under it, the Intermediate
        // row names the root already.
        let above = match signed_by(&self.root, ours.map(String::as_str)) {
            Err(why) if why == LOST => Some(Err(why)),
            _ if ca != Some(CaMode::Import) && !chained => None,
            above => Some(above),
        };
        let previous = previous_until(&self.root);
        let rows = report(
            &self.theme,
            &certs,
            own.as_deref(),
            ca,
            above,
            previous,
            Utc::now(),
        );
        self.maint.certs = Certs {
            rows,
            ca,
            refused: None,
            own,
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
        // Said for one Enter: a move or another Enter takes it away.
        self.maint.certs.refused = None;
        if self.move_row(&key, ACTIONS.len()) || key != Key::Enter {
            return;
        }
        if self.nav.row == 0 {
            return self.open_page(Page::Names);
        }
        if self.nav.row == 2 {
            let own = self.maint.certs.own.is_some();
            return self.open_page(if own { Page::Console } else { Page::ConsoleUse });
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
