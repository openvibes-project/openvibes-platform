//! The Configuration screen's state and keys (admin TUI spec §5): one form
//! per service, checked by the service's own type after every change; save
//! shows the changes, refuses a file changed on disk meanwhile, writes
//! through the root helper, then offers a restart.

use platform_host::{Host, Service, ServiceAction, Unit};

use super::{
    app::{App, Key},
    form::Form,
};

/// The longest value typed into a field.
const MAX_INPUT: usize = 4096;

/// What `y` confirms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Prompt {
    /// Write the file; the changes are shown.
    Save,
    /// Throw the unsaved changes away, then go on.
    Discard(Then),
    /// Restart the service whose file was just saved.
    Restart(Unit),
}

/// Where the operator goes once nothing is left unsaved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Then {
    /// Open this service's file (index into `Service::ALL`); the same index reloads.
    Service(usize),
    /// The Database screen (the next tab).
    Database,
    /// The Services screen (the previous tab).
    Services,
    Quit,
}

#[derive(Default)]
pub struct Configuration {
    /// Index into `Service::ALL`.
    pub service: usize,
    /// The file as a form; `None` when it could not be read or is not TOML.
    pub form: Option<Form>,
    pub selected: usize,
    /// The value being typed.
    pub editing: Option<String>,
    pub prompt: Option<Prompt>,
}

impl<H: Host> App<H> {
    /// Reads the selected service's file into a fresh form.
    pub fn load_config(&mut self) {
        let service = Service::ALL[self.config.service];
        self.config.selected = 0;
        self.config.editing = None;
        self.config.prompt = None;
        self.config.form = match self.host.read_config(service) {
            Ok(text) => match Form::parse(service, &text) {
                Ok(form) => Some(form),
                Err(error) => {
                    self.message = Some(format!("{}: {error}; fix it by hand", service.path()));
                    None
                }
            },
            Err(error) => {
                self.message = Some(error.to_string());
                None
            }
        };
    }

    fn dirty(&self) -> bool {
        self.config
            .form
            .as_ref()
            .is_some_and(|form| !form.changes().is_empty())
    }

    /// h/l service, j/k field, Enter edit, u undo, w save, R reload, Tab
    /// Services, q quit; while editing, keys type the value.
    pub(super) fn config_key(&mut self, key: Key) {
        if let Some(prompt) = self.config.prompt.take() {
            return self.answer(prompt, key == Key::Char('y'));
        }
        if self.config.editing.is_some() {
            return self.edit_key(key);
        }
        let count = Service::ALL.len();
        let fields = self
            .config
            .form
            .as_ref()
            .map_or(0, |form| form.fields().len());
        match key {
            Key::Char('j') | Key::Down if self.config.selected + 1 < fields => {
                self.config.selected += 1
            }
            Key::Char('k') | Key::Up => {
                self.config.selected = self.config.selected.saturating_sub(1)
            }
            Key::Char('l') | Key::Right => {
                self.leave(Then::Service((self.config.service + 1) % count))
            }
            Key::Char('h') | Key::Left => {
                self.leave(Then::Service((self.config.service + count - 1) % count))
            }
            Key::Char('R') => self.leave(Then::Service(self.config.service)),
            Key::Tab => self.leave(Then::Database),
            Key::BackTab => self.leave(Then::Services),
            Key::Char('q') => self.leave(Then::Quit),
            Key::Enter => {
                if let Some(form) = &self.config.form {
                    let field = form.fields()[self.config.selected];
                    if setup_owned(form, field.key) {
                        self.message = Some(SETUP_OWNED.into());
                        return;
                    }
                    self.config.editing = Some(form.get(field.key).unwrap_or_default());
                    self.message = None;
                }
            }
            Key::Char('u') => {
                if let Some(form) = &mut self.config.form {
                    let key = form.fields()[self.config.selected].key;
                    form.undo(key);
                }
            }
            Key::Char('w') => self.ask_save(),
            _ => {}
        }
    }

    fn edit_key(&mut self, key: Key) {
        let Some(buffer) = self.config.editing.as_mut() else {
            return;
        };
        match key {
            Key::Char(c) if !c.is_control() && buffer.chars().count() < MAX_INPUT => buffer.push(c),
            Key::Backspace => {
                buffer.pop();
            }
            Key::ClearLine => buffer.clear(),
            Key::Esc => {
                self.config.editing = None;
                self.message = None;
            }
            Key::Enter => {
                let input = buffer.clone();
                let Some(form) = self.config.form.as_mut() else {
                    return;
                };
                let field = form.fields()[self.config.selected];
                match form.set(field, &input) {
                    Ok(()) => {
                        self.config.editing = None;
                        self.message = None;
                    }
                    Err(error) => self.message = Some(format!("not accepted: {error}")),
                }
            }
            _ => {}
        }
    }

    fn leave(&mut self, then: Then) {
        if self.dirty() {
            self.config.prompt = Some(Prompt::Discard(then));
        } else {
            self.go(then);
        }
    }

    fn go(&mut self, then: Then) {
        match then {
            Then::Service(index) => {
                self.config.service = index;
                self.message = None;
                self.load_config();
            }
            Then::Database => self.open_database(),
            Then::Services => self.open(super::app::Tab::Services),
            Then::Quit => self.quit = true,
        }
    }

    fn ask_save(&mut self) {
        let Some(form) = &self.config.form else {
            return;
        };
        if form.changes().is_empty() {
            self.message = Some("nothing to save".into());
        } else if let Err(error) = &form.validity {
            self.message = Some(format!("cannot save: {error}"));
        } else {
            self.config.prompt = Some(Prompt::Save);
            self.message = None;
        }
    }

    fn answer(&mut self, prompt: Prompt, yes: bool) {
        match (prompt, yes) {
            (Prompt::Save, true) => self.save(),
            (Prompt::Discard(then), true) => self.go(then),
            (Prompt::Restart(unit), true) => {
                self.message = Some(
                    match self.host.service_action(unit, ServiceAction::Restart) {
                        Ok(()) => format!("restart requested for {}", unit.name()),
                        Err(error) => error.to_string(),
                    },
                );
            }
            _ => {}
        }
    }

    fn save(&mut self) {
        let Some(form) = &self.config.form else {
            return;
        };
        let (service, text) = (form.service, form.text());
        // Someone may have edited the file by hand since it was opened.
        match self.host.read_config(service) {
            Ok(current) if current == form.original => {}
            Ok(_) => {
                self.message = Some(format!(
                    "{} changed on disk since it was opened; R reloads it (your edits are dropped)",
                    service.path()
                ));
                return;
            }
            Err(error) => {
                self.message = Some(error.to_string());
                return;
            }
        }
        match self.host.write_config(service, &text) {
            Ok(()) => {
                // The file is now exactly this text; no second read.
                self.config.form = Form::parse(service, &text).ok();
                self.message = Some(format!("saved {}", service.path()));
                self.config.prompt = service.unit().map(Prompt::Restart);
            }
            Err(error) => self.message = Some(error.to_string()),
        }
    }
}

/// Why a field Setup owns does not open for editing (board #78).
const SETUP_OWNED: &str = "set by Setup: change ports with p (Change ports) on the Setup tab, \
                           which checks them and opens the firewall";

/// Listen addresses and the console's origin: Setup writes them from its
/// plan, checks the ports, opens the firewall and keeps `public_origin` in
/// step. Edited here, a Repair would undo them, and a changed console port
/// would answer 421 until then (board #78). Behind a reverse proxy the
/// console's listener is the operator's (Setup writes it only with direct
/// TLS), so it stays editable there.
pub(super) fn setup_owned(form: &Form, key: &str) -> bool {
    match (form.service, key) {
        (Service::Ingest | Service::Distribution, "listen")
        | (Service::Console, "public_origin") => true,
        (Service::Console, "development_listen") => form
            .get("transport_mode")
            .is_none_or(|mode| mode.trim_matches('"') == "direct_tls"),
        _ => false,
    }
}
