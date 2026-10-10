//! Questions, the sudo password in the bar, and service actions polled to
//! their one result line (admin TUI spec §2).

use std::time::{Duration, Instant};

use platform_host::{Host, Privileged, ServiceAction, Unit};

use super::{
    app::{App, Key},
    password::{PasswordPrompt, Typed},
    service::question_detail,
    services_text::readable,
    status::Fix,
    ui::bar::Bar,
};

/// How long a service action may take to show its result.
pub const ACTION_TIMEOUT: Duration = Duration::from_secs(30);

/// A question in the bar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Question {
    Service(Unit, ServiceAction),
    Quit,
}

/// A service action waiting for its unit to reach the asked state.
pub struct Pending {
    pub unit: Unit,
    pub action: ServiceAction,
    pub since: Instant,
    pub polled: Instant,
}

impl<H: Host> App<H> {
    /// Polls running work about once a second until its unit reaches the
    /// asked state, or the timeout passes.
    pub fn poll(&mut self, now: Instant) {
        self.tick_count = self.tick_count.wrapping_add(1);
        let Some(p) = &self.pending else { return };
        if now.saturating_duration_since(p.polled) < Duration::from_secs(1) {
            return;
        }
        let (unit, action, since) = (p.unit, p.action, p.since);
        self.refresh();
        let reached = self
            .services
            .iter()
            .find(|s| s.unit == unit)
            .is_some_and(|s| match action {
                ServiceAction::Stop => s.active != "active",
                _ => s.active == "active" && s.ready != Some(false),
            });
        let waited = now.saturating_duration_since(since);
        if reached {
            self.pending = None;
            self.outcome = Some((
                true,
                format!(
                    "{} {} ({} s)",
                    unit.label(),
                    done_text(action),
                    waited.as_secs()
                ),
            ));
            self.load_logs();
        } else if waited > ACTION_TIMEOUT {
            self.pending = None;
            let last = self
                .host
                .logs(unit, 1)
                .ok()
                .and_then(|l| l.last().cloned())
                .unwrap_or_default();
            let verb = if action == ServiceAction::Stop {
                "stop"
            } else {
                "start"
            };
            self.outcome = Some((
                false,
                format!(
                    "{} did not {verb} within {} s: {}",
                    unit.label(),
                    ACTION_TIMEOUT.as_secs(),
                    readable(&last)
                ),
            ));
            self.load_logs();
        } else if let Some(p) = &mut self.pending {
            p.polled = now;
        }
    }

    pub(super) fn question_key(&mut self, key: Key) {
        let Some((question, yes)) = self.question.take() else {
            return;
        };
        let answer = match key {
            Key::Left | Key::Right => {
                self.question = Some((question, !yes));
                return;
            }
            Key::Enter => yes,
            Key::Char('y') => true,
            Key::Char('n') | Key::Esc => false,
            _ => {
                self.question = Some((question, yes));
                return;
            }
        };
        if !answer {
            return;
        }
        match question {
            Question::Quit => self.quit = true,
            Question::Service(unit, action) => match self.host.service_action(unit, action) {
                Ok(()) => {
                    let now = Instant::now();
                    self.pending = Some(Pending {
                        unit,
                        action,
                        since: now,
                        polled: now,
                    });
                }
                Err(error) => self.outcome = Some((false, error.to_string())),
            },
        }
    }

    pub(super) fn prompt_key(&mut self, key: Key) {
        let Some((unit, mut prompt)) = self.prompt.take() else {
            return;
        };
        match prompt.key(key) {
            Typed::Pending => self.prompt = Some((unit, prompt)),
            Typed::Cancelled => {}
            Typed::Entered(secret) => {
                self.outcome = Some(
                    match self.host.privileged(Privileged::UnitEnable(unit), &secret) {
                        Ok(_) => (true, format!("{} now starts at boot", unit.label())),
                        Err(error) => (false, error.to_string()),
                    },
                );
                self.refresh();
            }
        }
    }

    pub(super) fn ask_fix(&mut self, fix: Fix) {
        if self.pending.is_some() {
            return;
        }
        match fix {
            Fix::Start(unit) => {
                self.question = Some((Question::Service(unit, ServiceAction::Start), true));
            }
            Fix::Enable(unit) => self.prompt = Some((unit, PasswordPrompt::default())),
        }
    }

    /// Quits, or asks first while a service action runs.
    pub(super) fn quit_or_ask(&mut self) {
        if self.pending.is_some() {
            self.question = Some((Question::Quit, true));
        } else {
            self.quit = true;
        }
    }

    /// The bar: `default`, unless a question, a prompt, running work or a
    /// result takes its place.
    pub(super) fn bar(&self, default: Bar) -> Bar {
        if let Some((question, yes)) = &self.question {
            let (question, detail) = match question {
                Question::Service(unit, action) => (
                    format!("{} {}?", capitalised(*action), unit.label()),
                    question_detail(*unit, *action).to_owned(),
                ),
                Question::Quit => (
                    "Quit while it runs?".to_owned(),
                    "it keeps running".to_owned(),
                ),
            };
            return Bar::Ask {
                question,
                detail,
                yes: *yes,
            };
        }
        if let Some((_, prompt)) = &self.prompt {
            return Bar::Typing {
                label: "Your password (sudo)".into(),
                shown: prompt.masked(),
                done: "Enable".into(),
            };
        }
        if let Some(p) = &self.pending {
            return Bar::Busy {
                text: format!("{} {}…", progressive(p.action), p.unit.label()),
                tick: self.tick_count,
            };
        }
        if let Some((ok, text)) = &self.outcome {
            return Bar::Done {
                ok: *ok,
                text: text.clone(),
            };
        }
        default
    }
}

fn capitalised(action: ServiceAction) -> &'static str {
    match action {
        ServiceAction::Start => "Start",
        ServiceAction::Stop => "Stop",
        ServiceAction::Restart => "Restart",
    }
}

fn progressive(action: ServiceAction) -> &'static str {
    match action {
        ServiceAction::Start => "Starting",
        ServiceAction::Stop => "Stopping",
        ServiceAction::Restart => "Restarting",
    }
}

fn done_text(action: ServiceAction) -> &'static str {
    match action {
        ServiceAction::Start => "started and ready",
        ServiceAction::Stop => "stopped",
        ServiceAction::Restart => "restarted and ready",
    }
}
