//! Maintenance › Certificates › Replace (certs2.py #3-4, certs4a.py #2-9):
//! a new intermediate, trusted beside the old one until agents move over
//! (`helper ca-replace`). With your own CA the install's request, paste
//! and file screens add the signed certificate, the root kept; when
//! OpenVIBES made the CA, the root key file kept offline at install is
//! picked and checked here first, as the helper checks it again. Replace
//! asks, then the password, then the step list and one result line.

use std::path::PathBuf;

use chrono::{NaiveDate, Utc};
use platform_host::{Host, StepState};
use platform_pki::Issuer;
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Page, Then, folder::Browse};
use crate::{
    setup::{pki::ROOT_CERT, plan::plan_of, replace::NOT_THE_KEY},
    tui::{
        app::{App, Key, Question},
        ca_request::{self, Picked, pick},
        install::{Stage, Which, steps::tilde},
        nav::Screen,
        run::{Call, Kind, Run, Work},
        status::wrap,
        ui::{
            bar::Bar,
            frame,
            list::{self, Row},
            logo::Header,
            steps,
        },
    },
};

const STEPS: [&str; 4] = [
    "Making the new intermediate",
    "Trusting the old and the new one",
    "Issuing the server certificates",
    "Restarting the services",
];

/// The page's state; your own CA's request is the install's (`app.install`).
#[derive(Debug, Default)]
pub struct Replace {
    /// This host's root: its PEM and name, or why it cannot be read.
    root: Option<Result<(String, String), String>>,
    /// The root key file picked, and its check.
    key: Option<(PathBuf, Result<(), String>)>,
    pick: Option<Browse>,
}

impl Replace {
    /// The file browser is open: every key is its own.
    pub fn picking(&self) -> bool {
        self.pick.is_some()
    }

    fn key_ok(&self) -> bool {
        matches!(self.key, Some((_, Ok(()))))
    }
}

fn replace_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Replace { .. }))
}

fn line(t: &crate::tui::ui::theme::Theme, said: Result<&str, &str>) -> Vec<Line<'static>> {
    let (text, style) = match said {
        Ok(ok) => (format!("✓ {ok}"), t.green()),
        Err(why) => (format!("✗ {why}"), t.red()),
    };
    let mut lines = vec![Line::raw("")];
    // The whole width: the result line of certs4a.py #9 is 78 columns.
    lines.extend(
        wrap(&text, 76, 2)
            .into_iter()
            .map(|l| Line::styled(format!("    {l}"), style)),
    );
    lines
}

fn draw_run<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let titles: Vec<String> = STEPS[usize::from(!app.maint.certs.quick)..]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    // One helper call does every step and prints each one it finished;
    // it reports only once it ends, so nothing is ticked before that.
    let out = match &run.states[0] {
        Some(StepState::Done(out)) => out.as_str(),
        _ => "",
    };
    let states: Vec<Option<StepState>> = titles
        .iter()
        .map(|title| {
            out.lines()
                .any(|l| l == title)
                .then(|| StepState::Done(String::new()))
        })
        .collect();
    let bar = if run.running() {
        Bar::Busy {
            text: format!("{}…", run.work.kind.doing()),
            tick: app.tick_count,
        }
    } else {
        Bar::only(&[("Enter", "Back")])
    };
    let area = frame::draw(frame, t, head, Some(&run.work.kind.doing()), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    lines.extend(steps::lines(t, &titles, &states, None, app.tick_count, 10));
    match &run.states[0] {
        _ if run.running() => {}
        Some(state) if !state.finished() => {
            lines.extend(line(t, Err(&ca_request::sentence(state.detail()))));
        }
        _ => lines.extend(line(
            t,
            Ok(&format!("{} ({})", run.work.kind.done(), run.took())),
        )),
    }
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = replace_run(app) {
        return draw_run(frame, head, app, run);
    }
    let replace = &app.maint.replace;
    if let Some(browse) = &replace.pick {
        return super::folder::draw_browse(frame, head, app, browse);
    }
    let t = &app.theme;
    let row = app.nav.row;
    let quick = app.maint.certs.quick;
    let install = &app.install;
    let home = install.home.as_deref();
    let root = replace
        .root
        .as_ref()
        .map(|r| r.as_ref().map(|(_, name)| name));
    let (note, rows, enter, said) = if quick {
        let file = match &replace.key {
            None => vec![Span::styled("not added yet", t.yellow())],
            Some((path, checked)) => vec![
                match checked {
                    Ok(()) => Span::styled("✓", t.green()),
                    Err(_) => Span::styled("✗", t.red()),
                },
                Span::raw(format!(" {}", tilde(&path.display().to_string(), home))),
            ],
        };
        let ready = replace.key_ok();
        let rows = vec![
            Row::Entry {
                name: vec![Span::raw("Root key file")],
                value: file,
            },
            Row::entry(
                "Replace",
                if ready {
                    "a new intermediate, signed here"
                } else {
                    "once the root key file is added"
                },
            ),
        ];
        let enter = match (row, &replace.key) {
            (0, None) => Some("Pick the file"),
            (0, Some(_)) => Some("Pick another file"),
            _ => ready.then_some("Replace"),
        };
        let said = match (&replace.key, root) {
            (Some((_, Ok(()))), _) => Some(Ok("The key matches the OpenVIBES root on this host.")),
            (Some((_, Err(why))), _) => Some(Err(why.as_str())),
            (None, Some(Err(why))) => Some(Err(why.as_str())),
            _ => None,
        };
        let note = "Needs the root key kept offline at install. Nothing changes until Replace.";
        (note, rows, enter, said)
    } else {
        let signed = match &install.signed {
            Some(who) => vec![
                Span::styled("✓ added", t.green()),
                Span::styled(format!(" · signed by {who}"), t.dim()),
            ],
            None => vec![Span::styled("not added yet", t.yellow())],
        };
        let kept = match root {
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
            3 if ready => Some("Replace"),
            _ => None,
        };
        let said = match (&install.error, root) {
            (Some(why), _) => Some(Err(why.as_str())),
            (None, Some(Err(why))) => Some(Err(why.as_str())),
            _ => None,
        };
        let note = "The same steps as at install. Nothing changes until Replace.";
        (note, rows, enter, said)
    };
    // While the request is made or the certificates are kept.
    let busy = app
        .run
        .as_ref()
        .filter(|r| r.running() && matches!(r.work.kind, Kind::Ca { .. }))
        .map(|r| Bar::Busy {
            text: format!("{}…", r.work.kind.doing()),
            tick: app.tick_count,
        });
    let keys: Vec<(&str, &str)> = enter.map(|e| ("Enter", e)).into_iter().collect();
    let bar = app.bar(busy.unwrap_or_else(|| Bar::keys(&keys)));
    let area = frame::draw(frame, t, head, Some("Replace the intermediate"), &bar);
    let mut lines = vec![Line::raw(""), Line::styled(format!("    {note}"), t.dim())];
    let height = 2 * rows.len() as u16 + 1;
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, row, &mut scroll, height, 26));
    app.nav.scroll.set(scroll);
    if let Some(said) = said {
        // The list's last line is the blank one before it.
        lines.pop();
        lines.extend(line(t, said));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_replace(&mut self) {
        // A replacement running is shown; one that ended is not news.
        if let Some(run) = replace_run(self) {
            if run.running() {
                return;
            }
            self.run = None;
        }
        let pem = std::fs::read_to_string(self.root.join(ROOT_CERT.trim_start_matches('/')));
        let root = pem
            .map_err(|e| format!("{ROOT_CERT}: {e}"))
            .and_then(|pem| {
                let name = platform_pki::issuer_common_name(&pem)
                    .map_err(|e| format!("{ROOT_CERT}: {e:?}"))?
                    .unwrap_or_else(|| "your CA".into());
                Ok((pem.trim().to_owned(), name))
            });
        self.maint.replace = Replace {
            root: Some(root),
            ..Replace::default()
        };
        if self.maint.certs.quick {
            self.nav.row = 0;
            return;
        }
        // Your own CA: the install's request, made again or reused, for
        // this host's names; the root stays the one agents trust.
        let install = &mut self.install;
        install.request = None;
        install.signed = None;
        install.cert = None;
        install.root_pem = None;
        install.root_added = None;
        install.paste = None;
        install.pick = None;
        install.error = None;
        if let Some(plan) = self.host.setup_plan().ok().and_then(|t| plan_of(&t).ok()) {
            install.hostname = plan.hostname;
        }
        self.nav.row = 1;
        if matches!(self.maint.replace.root, Some(Ok(_))) {
            self.make_request();
        }
    }

    pub(super) fn replace_key(&mut self, key: Key) {
        if self.maint.replace.picking() {
            return self.root_key_picked(key);
        }
        if let Some(run) = replace_run(self) {
            if !run.running() && key == Key::Enter {
                self.back();
                self.read_certs();
            }
            return;
        }
        let quick = self.maint.certs.quick;
        if self.move_row(&key, if quick { 2 } else { 4 }) || key != Key::Enter {
            return;
        }
        let made = self.install.request.is_some();
        match (quick, self.nav.row) {
            (true, 0) => {
                let home = self.install.home.clone().unwrap_or_else(|| "/".into());
                self.maint.replace.pick = Some(Browse::files_at(&home));
                self.nav.row = 0;
            }
            (true, _) if self.maint.replace.key_ok() => self.ask_replace(),
            (false, 0 | 1) if !made => self.make_request(),
            (false, 0) => self.nav.go(Screen::Install(Stage::Request)),
            (false, 1) => {
                // The kept root goes with the signed certificate (ca-accept).
                if let Some(Ok((pem, name))) = &self.maint.replace.root {
                    self.install.root_pem = Some(pem.clone());
                    self.install.root_added = Some(name.clone());
                }
                self.nav.go(Screen::Install(Stage::Add(Which::Signed)));
            }
            (false, 3) if self.install.accepted() => self.ask_replace(),
            _ => {}
        }
    }

    /// The file browser's keys; a file picked is checked at once against
    /// this host's root (at most 64 KiB read, as the operator).
    fn root_key_picked(&mut self, key: Key) {
        let replace = &mut self.maint.replace;
        let path = match pick(&mut replace.pick, &mut self.nav.row, &self.nav.scroll, key) {
            Picked::Nothing => return,
            Picked::Closed => {
                self.nav.row = 0;
                return;
            }
            Picked::File(path) => path,
        };
        let checked = match &replace.root {
            Some(Ok((root, _))) => ca_request::read(&path)
                .map_err(|e| format!("{}: {e}", path.display()))
                .and_then(|key| {
                    Issuer::load(root, &key)
                        .map(|_| ())
                        .map_err(|_| NOT_THE_KEY.to_owned())
                }),
            Some(Err(why)) => Err(why.clone()),
            None => Err(NOT_THE_KEY.to_owned()),
        };
        self.nav.row = usize::from(checked.is_ok());
        replace.key = Some((path, checked));
        replace.pick = None;
    }

    fn ask_replace(&mut self) {
        self.question = Some((
            Question::Maint {
                text: "Replace the intermediate?".into(),
                detail: "agents keep working".into(),
                then: Then::Replace,
            },
            true,
        ));
    }

    pub(super) fn replace_yes(&mut self) {
        let key = match &self.maint.replace.key {
            Some((path, Ok(()))) if self.maint.certs.quick => Some(path.display().to_string()),
            _ => None,
        };
        let done = "Replaced".to_owned();
        let work = Work::new(Kind::Replace { done }, vec![Call::CaReplace(key)]);
        self.begin(work, 0);
    }

    /// A run ended: your own CA's certificate kept goes to Replace; a
    /// replacement says when agents have moved over.
    pub(super) fn replace_ended(&mut self) {
        let quick = self.maint.certs.quick;
        let Some(run) = self.run.as_mut() else { return };
        match &mut run.work.kind {
            Kind::Ca { .. }
                if self.nav.screen == Screen::Maint(Page::Replace) && self.install.accepted() =>
            {
                self.nav.row = 3;
            }
            Kind::Replace { done } => {
                let Some(StepState::Done(out)) = &run.states[0] else {
                    return;
                };
                // `done<TAB>NEW UNTIL<TAB>PREVIOUS UNTIL`; the old one is
                // trusted one day longer than an agent certificate lasts.
                let until = out
                    .lines()
                    .find_map(|l| l.strip_prefix("done\t"))
                    .and_then(|l| l.split('\t').nth(1))
                    .and_then(|d| NaiveDate::parse_from_str(d.trim(), "%Y-%m-%d").ok());
                if let Some(until) = until {
                    let days = (until - Utc::now().date_naive()).num_days() - 1;
                    *done = format!("Replaced · agents move over in {days} days");
                }
                if quick {
                    done.push_str(" · put the key offline again");
                }
            }
            _ => {}
        }
    }
}
