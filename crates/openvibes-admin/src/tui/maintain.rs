//! The Update (§6.5a) and Uninstall (§6.5) screens of the Setup tab: what
//! to do and the backup, then the job runs like any other.

use platform_host::Host;

use super::{
    app::{App, Key},
    jobs::Job,
    setup::{After, Phase},
};
use crate::setup::plan::Plan;

pub const UPDATE_START_ROW: usize = 1;
pub const UNINSTALL_START_ROW: usize = 3;

impl<H: Host> App<H> {
    pub(super) fn open_update(&mut self) {
        self.setup.packages = self.host.packages().unwrap_or_else(|error| {
            self.message = Some(error.to_string());
            Vec::new()
        });
        let home = self.setup.home.clone().unwrap_or_default();
        self.setup.backup = format!("{home}/openvibes-before-update.dump");
        self.setup.row2 = 0;
        self.setup.editing = false;
        self.setup.phase = Phase::Update;
    }

    pub(super) fn open_uninstall(&mut self) {
        let home = self.setup.home.clone().unwrap_or_default();
        self.setup.backup = format!("{home}/openvibes-backup.dump");
        self.setup.confirm.clear();
        self.setup.everything = false;
        self.setup.row2 = 0;
        self.setup.editing = false;
        self.setup.phase = Phase::Uninstall;
    }

    /// The text field under the cursor on these screens.
    fn maintain_field(&mut self) -> Option<&mut String> {
        match (self.setup.phase, self.setup.row2) {
            (Phase::Update, 0) => Some(&mut self.setup.backup),
            (Phase::Uninstall, 1) if self.setup.everything => Some(&mut self.setup.backup),
            (Phase::Uninstall, 2) if self.setup.everything => Some(&mut self.setup.confirm),
            _ => None,
        }
    }

    /// Typing into a field; true when the key was used.
    fn edit(&mut self, key: Key) -> bool {
        if !self.setup.editing {
            return false;
        }
        let Some(field) = self.maintain_field() else {
            self.setup.editing = false;
            return false;
        };
        match key {
            Key::Char(c) if field.len() < 512 => field.push(c),
            Key::Backspace => {
                field.pop();
            }
            Key::ClearLine => field.clear(),
            Key::Enter | Key::Esc => self.setup.editing = false,
            _ => {}
        }
        true
    }

    fn backup_args(&self) -> Vec<String> {
        let path = self.setup.backup.trim();
        if path.is_empty() {
            Vec::new()
        } else {
            vec!["--backup".into(), path.into()]
        }
    }

    pub(super) fn update_key(&mut self, key: Key) {
        if self.edit(key) {
            return;
        }
        match key {
            Key::Char('j') | Key::Down if self.setup.row2 < UPDATE_START_ROW => {
                self.setup.row2 += 1
            }
            Key::Char('k') | Key::Up => self.setup.row2 = self.setup.row2.saturating_sub(1),
            Key::Enter if self.setup.row2 == UPDATE_START_ROW => {
                self.setup.job_args = self.backup_args();
                self.setup.prompt = Default::default();
                self.setup.phase = Phase::Password(After::Job(Job::Update));
            }
            Key::Enter => self.setup.editing = self.maintain_field().is_some(),
            Key::Esc => self.setup.phase = Phase::Status,
            _ => {}
        }
    }

    pub(super) fn uninstall_key(&mut self, key: Key) {
        if self.edit(key) {
            return;
        }
        match key {
            // Only rows on screen take the focus (#74): the backup and the
            // typed name exist for Remove everything alone.
            Key::Char('j') | Key::Down => {
                let rows = self.uninstall_rows();
                if let Some(&next) = rows.iter().find(|&&r| r > self.setup.row2) {
                    self.setup.row2 = next;
                }
            }
            Key::Char('k') | Key::Up => {
                let rows = self.uninstall_rows();
                self.setup.row2 = rows
                    .iter()
                    .rev()
                    .copied()
                    .find(|&r| r < self.setup.row2)
                    .unwrap_or(0);
            }
            Key::Char(' ') if self.setup.row2 == 0 => {
                self.setup.everything = !self.setup.everything
            }
            Key::Enter if self.setup.row2 == UNINSTALL_START_ROW => self.start_uninstall(),
            Key::Enter => self.setup.editing = self.maintain_field().is_some(),
            Key::Esc => self.setup.phase = Phase::Status,
            _ => {}
        }
    }

    /// The Uninstall screen's rows that are shown, top to bottom.
    fn uninstall_rows(&self) -> &'static [usize] {
        if self.setup.everything {
            &[0, 1, 2, UNINSTALL_START_ROW]
        } else {
            &[0, UNINSTALL_START_ROW]
        }
    }

    fn start_uninstall(&mut self) {
        let plan = match self
            .host
            .setup_plan()
            .map_err(|e| e.to_string())
            .and_then(|text| toml::from_str::<Plan>(&text).map_err(|e| e.to_string()))
        {
            Ok(plan) => plan,
            Err(error) => {
                self.message = Some(error);
                return;
            }
        };
        let components: Vec<&str> = plan.components.iter().map(|c| c.name()).collect();
        let mut args = vec!["--components".to_owned(), components.join(",")];
        if self.setup.everything {
            if self.setup.confirm.trim() != plan.hostname {
                self.message = Some(format!(
                    "type this host's name ({}) to confirm Remove everything",
                    plan.hostname
                ));
                return;
            }
            args.extend(self.backup_args());
            args.extend(["--confirm".into(), plan.hostname.clone()]);
        }
        self.message = None;
        self.setup.job_args = args;
        self.setup.prompt = Default::default();
        self.setup.phase = Phase::Password(After::Job(Job::Remove));
    }
}
