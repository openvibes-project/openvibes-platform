//! Where the operator is (spec §3): a stack of screens. Enter opens, Esc
//! pops, ? opens Help, q quits from Home. Today's Setup, Configuration and
//! Database screens ("legacy") are reached from Maintenance and keep their
//! own keys; Tab and q are no longer theirs, and Esc leaves them only when
//! nothing is being typed or asked (sub-projects 2 and 3 replace them).

use std::cell::Cell;

use platform_host::{Host, Unit};
use ratatui::Frame;

use super::{
    app::{App, Key, Tab},
    configuration::{Prompt, Then},
    home, service,
    setup::Phase,
    status,
    ui::{frame, list::Scroll, logo::Header},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Screen {
    Home,
    Status,
    Service(Unit),
    Log(Unit),
    Maintenance,
    Help(Box<Screen>),
    Legacy,
}

#[derive(Clone, Debug)]
pub struct Nav {
    pub screen: Screen,
    pub back: Vec<Screen>,
    pub row: usize,
    pub scroll: Cell<Scroll>,
}

impl Nav {
    pub fn new(screen: Screen) -> Self {
        Self {
            screen,
            back: Vec::new(),
            row: 0,
            scroll: Cell::default(),
        }
    }

    pub fn go(&mut self, to: Screen) {
        let from = std::mem::replace(&mut self.screen, to);
        self.back.push(from);
        self.row = 0;
        self.scroll.set(Scroll::default());
    }

    /// Back one screen; false when there is nowhere to go.
    pub fn pop(&mut self) -> bool {
        let Some(previous) = self.back.pop() else {
            return false;
        };
        self.screen = previous;
        self.row = 0;
        self.scroll.set(Scroll::default());
        true
    }
}

/// The location line's left part and the update notice.
pub fn header<H: Host>(app: &App<H>) -> (String, Option<String>) {
    let where_ = match &app.nav.screen {
        Screen::Home => String::new(),
        Screen::Status => " · Status".into(),
        Screen::Service(unit) | Screen::Log(unit) => format!(" · Status › {}", unit.label()),
        Screen::Maintenance => " · Maintenance".into(),
        Screen::Help(_) => " · Help".into(),
        Screen::Legacy => match app.tab {
            Tab::Setup if !app.setup_done() => " · Install".into(),
            Tab::Setup => " · Maintenance › Setup".into(),
            Tab::Configuration => " · Maintenance › Settings files".into(),
            _ => " · Maintenance › Database".into(),
        },
    };
    (format!("{}{where_}", app.hostname), app.update.clone())
}

pub fn render<H: Host>(frame: &mut Frame, app: &App<H>) {
    if frame::too_small(frame) {
        return;
    }
    let (location, update) = header(app);
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let head = Header {
        location: &location,
        version: &version,
        update: update.as_deref(),
    };
    match &app.nav.screen {
        Screen::Legacy => {
            let body = frame::legacy(frame, &app.theme, &head);
            super::legacy_view(frame, body, app);
        }
        Screen::Home => home::draw(frame, &head, app),
        Screen::Maintenance => home::draw_maintenance(frame, &head, app),
        Screen::Status => status::draw(frame, &head, app),
        Screen::Service(unit) => service::draw(frame, &head, app, *unit),
        Screen::Log(unit) => service::draw_log(frame, &head, app, *unit),
        Screen::Help(from) => home::draw_help(frame, &head, app, from),
    }
}

impl<H: Host> App<H> {
    /// The legacy screen has nothing typed, asked or running.
    pub fn legacy_at_rest(&self) -> bool {
        match self.tab {
            // A stopped run's Esc is its own: back to Setup's status (#73).
            Tab::Setup => matches!(self.setup.phase, Phase::Status | Phase::Finished),
            Tab::Configuration => self.config.editing.is_none() && self.config.prompt.is_none(),
            Tab::Database => self.database.confirm.is_none(),
            Tab::Services | Tab::Health => true,
        }
    }

    pub(super) fn legacy_key(&mut self, key: Key) {
        match key {
            Key::Tab | Key::BackTab => {}
            // q quits from Home only, but is typed into a value.
            Key::Char('q') if (self.setup_done() || self.tab != Tab::Setup) && !self.typing() => {}
            Key::Esc if self.legacy_at_rest() && self.setup_done() => {
                if self.tab == Tab::Configuration && self.config_dirty() {
                    self.config.prompt = Some(Prompt::Discard(Then::Back));
                } else {
                    self.back();
                }
            }
            _ => self.legacy_dispatch(key),
        }
    }

    /// A value or password is being typed on the legacy screen.
    fn typing(&self) -> bool {
        match self.tab {
            Tab::Setup => self.setup.editing || matches!(self.setup.phase, Phase::Password(_)),
            Tab::Configuration => self.config.editing.is_some(),
            Tab::Database | Tab::Services | Tab::Health => false,
        }
    }

    /// Back one screen; Home when there is none (a fresh install, finished).
    pub(super) fn back(&mut self) {
        if !self.nav.pop() {
            self.nav = Nav::new(Screen::Home);
        }
    }
}
