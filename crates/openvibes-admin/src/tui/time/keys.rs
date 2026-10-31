//! The Time page's keys and what a finished run does.

use platform_host::Host;

use super::{At, TimePage, draw::time_run};
use crate::tui::{
    app::{App, Key, Question},
    kind::Kind,
    maint::Then,
    run::{Call, Work},
};

impl<H: Host> App<H> {
    /// Opens the page: reads the clock settings again.
    pub(in crate::tui) fn open_time(&mut self) {
        self.nav.row = 0;
        if time_run(self).is_some_and(|r| !r.running()) {
            self.run = None;
        }
        self.maint.time = TimePage::from_info(self.host.time_info());
    }

    fn time_at(&self) -> Option<At> {
        self.maint.time.rows().get(self.nav.row).copied()
    }

    fn time_typed(&mut self, key: Key) {
        let at = self.time_at();
        let page = &mut self.maint.time;
        let Some(text) = page.typing.as_mut() else {
            return;
        };
        match key {
            Key::Char(c) if !c.is_control() && text.len() < 253 => text.push(c),
            Key::Backspace => {
                text.pop();
            }
            Key::ClearLine => text.clear(),
            Key::Enter => {
                let typed = std::mem::take(text).trim().to_owned();
                let ok = at.is_some_and(|a| matches!(TimePage::note_for(a, &typed), Some(Ok(_))));
                if !ok {
                    page.typing = Some(typed);
                    return;
                }
                match at {
                    Some(At::Servers) => page.servers = typed,
                    Some(At::Zone) => page.zone = typed,
                    _ => {}
                }
                page.typing = None;
                page.note = None;
                let last = page.rows().len().saturating_sub(1);
                self.nav.row = self.nav.row.min(last);
                return;
            }
            Key::Esc => {
                page.typing = None;
                page.note = None;
                return;
            }
            _ => return,
        }
        if let (Some(at), Some(typed)) = (at, &self.maint.time.typing) {
            self.maint.time.note = TimePage::note_for(at, typed);
        }
    }

    pub(in crate::tui) fn time_key(&mut self, key: Key) {
        if self.maint.time.typing() {
            return self.time_typed(key);
        }
        if let Some(run) = time_run(self) {
            if run.running() || key != Key::Enter {
                return;
            }
            if run.ok() {
                self.open_time();
            } else if let Some(at) = run.stopped_at() {
                let work = run.work.clone();
                self.begin(work, at);
            }
            return;
        }
        let count = self.maint.time.rows().len();
        if self.move_row(&key, count) || key != Key::Enter {
            return;
        }
        let page = &mut self.maint.time;
        match self.nav.row.min(count.saturating_sub(1)) {
            0 => page.typing = Some(page.servers.clone()),
            1 => page.typing = Some(page.zone.clone()),
            _ => return self.ask_time_apply(),
        }
        if let Some(at) = self.time_at() {
            self.maint.time.note = self
                .maint
                .time
                .typing
                .as_deref()
                .and_then(|typed| TimePage::note_for(at, typed));
        }
    }

    fn ask_time_apply(&mut self) {
        if let Some(why) = super::super::maint::busy(self) {
            self.outcome = Some((false, why));
            return;
        }
        if let Err(why) = self.maint.time.args() {
            self.outcome = Some((false, format!("✗ {why}")));
            return;
        }
        self.question = Some((
            Question::Maint {
                text: "Change the time settings?".into(),
                detail: "restarts the time service".into(),
                then: Then::TimeApply,
            },
            true,
        ));
    }

    pub(in crate::tui) fn time_apply_yes(&mut self) {
        match self.maint.time.args() {
            Ok(args) => self.begin(Work::new(Kind::Time, vec![Call::TimeSet(args)]), 0),
            Err(why) => self.outcome = Some((false, format!("✗ {why}"))),
        }
    }
}
