//! `App`'s side of background work: asking for the password in the bar,
//! starting a run, taking what the worker reports, and quitting while work
//! runs. The run itself is in `run.rs`.

use std::{sync::mpsc::TryRecvError, time::Instant};

use platform_host::{Host, Secret, StepState};
use ratatui::text::Span;

use super::{
    app::{App, Key, Question},
    password::{PasswordPrompt, Typed},
    run::{Asking, Run, Work, work_through},
    ui::bar::SPINNER,
};

impl<H: Host> App<H> {
    /// Starts `work` at `from`: the password first, unless sudo needs none
    /// (root). One action at a time; reads may run beside it.
    pub(super) fn begin(&mut self, work: Work, from: usize) {
        if !work.kind.background() && self.run.as_ref().is_some_and(Run::running) {
            self.outcome = Some((false, "Wait: other work is still running".into()));
            return;
        }
        if self.host.needs_password() {
            self.asking = Some(Asking {
                work,
                from,
                prompt: PasswordPrompt::default(),
                resume: false,
            });
        } else {
            self.start(work, from, Secret::new(String::new()), false);
        }
    }

    /// Starts reads that need no password.
    pub(super) fn read(&mut self, work: Work) {
        self.start(work, 0, Secret::new(String::new()), false);
    }

    pub(super) fn asking_key(&mut self, key: Key) {
        let Some(mut asking) = self.asking.take() else {
            return;
        };
        match asking.prompt.key(key) {
            Typed::Pending => self.asking = Some(asking),
            Typed::Cancelled if asking.resume => {
                let slot = if asking.work.kind.background() {
                    &mut self.load
                } else {
                    &mut self.run
                };
                if let Some(run) = slot.as_mut() {
                    run.states[asking.from] = Some(StepState::Failed(
                        "no password given: nothing more was run".into(),
                    ));
                }
            }
            Typed::Cancelled => {}
            Typed::Entered(secret) => self.start(asking.work, asking.from, secret, asking.resume),
        }
    }

    fn start(&mut self, work: Work, from: usize, secret: Secret, resume: bool) {
        let now = Instant::now();
        let background = work.kind.background();
        let slot = if background {
            &mut self.load
        } else {
            &mut self.run
        };
        // Try again (from > 0) and a resumed run keep the steps already done.
        let mut run = match slot.take() {
            Some(old) if old.work == work && (resume || from > 0) => old,
            _ => Run::new(work.clone(), now),
        };
        if !resume {
            run.wrong = 0;
        }
        for state in &mut run.states[from..] {
            *state = None;
        }
        run.at = from;
        run.ended = None;
        let mut again = false;
        match &self.worker {
            Some(worker) => run.rx = Some(worker(work, from, secret)),
            None => work_through(&self.host, &work, from, &secret, |p| {
                again |= run.take(p, now);
                true
            }),
        }
        *slot = Some(run);
        if again {
            self.ask_again(background);
        }
    }

    /// The password was wrong: ask again with the tries left, or stop at three.
    fn ask_again(&mut self, background: bool) {
        let slot = if background {
            &mut self.load
        } else {
            &mut self.run
        };
        let Some(run) = slot.as_mut() else { return };
        run.wrong += 1;
        if run.wrong >= 3 {
            run.states[run.at] = Some(StepState::Failed(
                "three wrong passwords: nothing more was run".into(),
            ));
            return;
        }
        let mut prompt = PasswordPrompt::default();
        prompt.failures = run.wrong;
        self.asking = Some(Asking {
            work: run.work.clone(),
            from: run.at,
            prompt,
            resume: true,
        });
    }

    /// Takes what the workers reported; quits when asked to wait for it.
    pub(super) fn poll_runs(&mut self, now: Instant) {
        for background in [false, true] {
            let slot = if background {
                &mut self.load
            } else {
                &mut self.run
            };
            let Some(run) = slot.as_mut() else { continue };
            let mut again = false;
            while let Some(rx) = &run.rx {
                match rx.try_recv() {
                    Ok(progress) => again |= run.take(progress, now),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        run.rx = None;
                        if run.running() {
                            let main = run.work.calls.len();
                            let next = (0..main).find(|&i| run.states[i].is_none());
                            if let Some(i) =
                                next.or_else(|| run.states.iter().position(Option::is_none))
                            {
                                run.states[i] =
                                    Some(StepState::Failed("the work stopped unexpectedly".into()));
                            }
                            run.ended = Some(now);
                        }
                    }
                }
            }
            if again {
                self.ask_again(background);
            }
        }
        if self.quit_when_done
            && self.asking.is_none()
            && !self.run.as_ref().is_some_and(Run::running)
        {
            self.quit = true;
        }
    }

    /// Ctrl+C: while work runs, as `q` (it asks); a second one quits at once.
    pub fn interrupt(&mut self) {
        let running = self.run.as_ref().is_some_and(Run::running);
        if running && !self.quit_when_done && !matches!(self.question, Some((Question::Quit, _))) {
            self.question = Some((Question::Quit, true));
        } else {
            self.quit = true;
        }
    }

    /// Home's note on the current or last action.
    pub(super) fn work_note(&self) -> Option<Vec<Span<'static>>> {
        let run = self.run.as_ref()?;
        let t = &self.theme;
        Some(if run.running() {
            vec![
                Span::styled(SPINNER[self.tick_count % SPINNER.len()], t.teal()),
                Span::raw(format!(" {}…", run.work.kind.doing())),
            ]
        } else if run.ok() {
            vec![
                Span::styled("✓", t.green()),
                Span::raw(format!(" {}", run.work.kind.done())),
            ]
        } else {
            vec![
                Span::styled("✗", t.red()),
                Span::raw(format!(" {} · see Maintenance", run.work.kind.stopped())),
            ]
        })
    }
}
