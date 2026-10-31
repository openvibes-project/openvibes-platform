//! System › SSH, on the appliance (spec §7; system.py): whether keys,
//! passwords or both may sign in over SSH. Apply runs `ssh-set`, which
//! checks the file with `sshd -t` before `sshd` reloads. Open sessions stay.

use platform_host::{Host, ssh::SshInfo};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    app::{App, Key, Question},
    kind::Kind,
    maint::{Then, failure},
    network::draw_run,
    run::{Call, Run, Work},
    status::wrap,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};

/// A page row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum At {
    Keys,
    Passwords,
    Apply,
}

/// The page's state: what the host says and the choice made.
#[derive(Debug, Default)]
pub struct SshPage {
    /// As read when the page opened; `None`: no `sshd` to manage.
    pub info: Option<SshInfo>,
    /// For System's menu line: read when System opens.
    pub menu: Option<String>,
    pub keys: bool,
    pub passwords: bool,
    /// Said under the list.
    pub said: Option<String>,
}

impl SshPage {
    pub fn from_info(info: Option<SshInfo>) -> Self {
        let Some(info) = info else {
            return Self::default();
        };
        SshPage {
            keys: info.keys,
            passwords: info.passwords,
            menu: Some(platform_host::ssh::menu_line(&info)),
            info: Some(info),
            said: None,
        }
    }

    pub fn changed(&self) -> bool {
        self.info
            .is_some_and(|i| i.keys != self.keys || i.passwords != self.passwords)
    }

    pub fn rows(&self) -> Vec<At> {
        let mut rows = vec![At::Keys, At::Passwords];
        if self.changed() {
            rows.push(At::Apply);
        }
        rows
    }

    /// Turns a way in on or off; the last one cannot be turned off.
    fn toggle(&mut self, at: At) {
        let (keys, passwords) = match at {
            At::Keys => (!self.keys, self.passwords),
            At::Passwords => (self.keys, !self.passwords),
            At::Apply => return,
        };
        match platform_host::ssh::check(keys, passwords) {
            Ok(()) => {
                (self.keys, self.passwords) = (keys, passwords);
                self.said = None;
            }
            Err(why) => self.said = Some(why),
        }
    }

    /// The `ssh-set` arguments.
    fn args(&self) -> Vec<String> {
        let word = |on: bool| if on { "yes" } else { "no" }.to_owned();
        vec![
            "--keys".into(),
            word(self.keys),
            "--passwords".into(),
            word(self.passwords),
        ]
    }

    /// Passwords go off and this account has no key to sign in with.
    fn locks_out(&self) -> bool {
        !self.passwords && self.info.is_some_and(|i| i.has_keys == Some(false))
    }
}

fn ssh_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Ssh))
}

fn row<H: Host>(app: &App<H>, page: &SshPage, at: At) -> Row {
    let t = &app.theme;
    let check = |on: bool, name: &str, value: &str| Row::Entry {
        name: vec![
            Span::styled(
                if on { "[x]" } else { "[ ]" },
                if on { t.green() } else { t.dim() },
            ),
            Span::raw(format!(" {name}")),
        ],
        value: vec![Span::styled(value.to_owned(), t.dim())],
    };
    match at {
        At::Keys => check(page.keys, "Allow keys", "public keys sign in"),
        At::Passwords => check(
            page.passwords,
            "Allow passwords",
            "the account password signs in",
        ),
        At::Apply => Row::Entry {
            name: vec![Span::raw("Apply")],
            value: vec![Span::styled(
                "checked first, then sshd reloads".to_owned(),
                t.dim(),
            )],
        },
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = ssh_run(app) {
        return draw_run(frame, head, app, run, "SSH", "Try again runs it once more.");
    }
    let t = &app.theme;
    let page = &app.maint.ssh;
    if page.info.is_none() {
        let area = frame::draw(frame, t, head, Some("SSH"), &app.bar(Bar::act(&[])));
        let lines = failure(t, "This host has no sshd to manage.", "");
        return frame.render_widget(Paragraph::new(lines), area);
    }
    let rows = page.rows();
    let at = rows.get(app.nav.row).copied();
    let bar = match at {
        Some(At::Apply) => Bar::keys(&[("Enter", "Apply")]),
        _ => Bar::keys(&[("Space", "Select/deselect")]),
    };
    let area = frame::draw(frame, t, head, Some("SSH"), &app.bar(bar));
    let mut lines = Vec::new();
    if let Some(said) = &page.said {
        lines.extend(
            wrap(said, 72, 2)
                .into_iter()
                .map(|l| Line::styled(format!("    {l}"), t.yellow())),
        );
    } else {
        let help = match at {
            Some(At::Apply) if page.locks_out() => {
                "This account has no authorized key. With passwords off nobody could sign in over SSH; the console still takes the password."
            }
            Some(At::Apply) => "Open sessions stay; new ones follow the new choice.",
            _ => "At least one of the two stays on.",
        };
        lines.extend(
            wrap(help, 72, 2)
                .into_iter()
                .map(|l| Line::styled(format!("    {l}"), t.dim())),
        );
    }
    lines.push(Line::raw(""));
    let list_rows: Vec<Row> = rows.iter().map(|r| row(app, page, *r)).collect();
    let height = area
        .height
        .saturating_sub(u16::try_from(lines.len()).unwrap_or(u16::MAX));
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
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Opens the page: reads the SSH settings again.
    pub(super) fn open_ssh(&mut self) {
        self.nav.row = 0;
        if ssh_run(self).is_some_and(|r| !r.running()) {
            self.run = None;
        }
        self.maint.ssh = SshPage::from_info(self.host.ssh_info());
    }

    pub(super) fn ssh_key(&mut self, key: Key) {
        if let Some(run) = ssh_run(self) {
            if run.running() || key != Key::Enter {
                return;
            }
            if run.ok() {
                self.open_ssh();
            } else if let Some(at) = run.stopped_at() {
                let work = run.work.clone();
                self.begin(work, at);
            }
            return;
        }
        let count = self.maint.ssh.rows().len();
        let space = key == Key::Char(' ');
        if self.move_row(&key, count) || !(key == Key::Enter || space) {
            return;
        }
        let Some(at) = self.maint.ssh.rows().get(self.nav.row).copied() else {
            return;
        };
        match at {
            At::Apply if key == Key::Enter => self.ask_ssh_apply(),
            At::Apply => {}
            toggle => {
                self.maint.ssh.toggle(toggle);
                let last = self.maint.ssh.rows().len().saturating_sub(1);
                self.nav.row = self.nav.row.min(last);
            }
        }
    }

    fn ask_ssh_apply(&mut self) {
        if let Some(why) = super::maint::busy(self) {
            self.outcome = Some((false, why));
            return;
        }
        let (text, detail, then, yes_first) = if self.maint.ssh.locks_out() {
            (
                "This account has no authorized key. Turn passwords off anyway?",
                "nobody could sign in over SSH; the console still takes the password",
                Then::SshLockOut,
                false,
            )
        } else {
            (
                "Change how people sign in over SSH?",
                "sshd is checked first; open sessions stay",
                Then::SshApply,
                true,
            )
        };
        self.question = Some((
            Question::Maint {
                text: text.into(),
                detail: detail.into(),
                then,
            },
            yes_first,
        ));
    }

    /// The second, deliberate yes that lock-out needs.
    pub(super) fn ask_ssh_really(&mut self) {
        self.question = Some((
            Question::Maint {
                text: "Lock SSH sign-in until a key is added?".into(),
                detail: "add a key at the console, or turn passwords on again here".into(),
                then: Then::SshApply,
            },
            false,
        ));
    }

    pub(super) fn ssh_apply_yes(&mut self) {
        let args = self.maint.ssh.args();
        self.begin(Work::new(Kind::Ssh, vec![Call::SshSet(args)]), 0);
    }
}
