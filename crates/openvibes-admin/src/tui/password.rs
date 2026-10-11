//! The password prompt for privileged steps (admin TUI spec §3): typed text
//! is masked, held in zeroized memory, and handed over once.

use platform_host::Secret;
use zeroize::Zeroizing;

use super::app::Key;

const MAX: usize = 256;

#[derive(Default)]
pub struct PasswordPrompt {
    typed: Zeroizing<String>,
    /// Wrong passwords so far; three close the prompt.
    pub failures: u8,
}

pub enum Typed {
    Pending,
    Cancelled,
    Entered(Secret),
}

impl PasswordPrompt {
    /// What has been typed so far (tests).
    #[cfg(test)]
    pub fn typed(&self) -> &str {
        &self.typed
    }

    pub fn key(&mut self, key: Key) -> Typed {
        match key {
            Key::Char(c) if self.typed.chars().count() < MAX => {
                self.typed.push(c);
                Typed::Pending
            }
            Key::Backspace => {
                self.typed.pop();
                Typed::Pending
            }
            Key::ClearLine => {
                self.typed.clear();
                Typed::Pending
            }
            Key::Esc => {
                self.typed.clear();
                Typed::Cancelled
            }
            Key::Enter => Typed::Entered(Secret::new(std::mem::take(&mut *self.typed))),
            _ => Typed::Pending,
        }
    }

    pub fn masked(&self) -> String {
        "*".repeat(self.typed.chars().count())
    }
}
