//! Where the operator is (spec §3): a stack of screens. Enter opens, Esc
//! pops (back to the row and window it left), ? opens Help, q quits from
//! Home. The Settings files screen ("legacy") is reached from
//! Maintenance and keeps its own keys; q is no longer its, and Esc leaves
//! it only when nothing is being typed or asked (sub-project 2 replaces
//! it). The install has its own screens (`install`).

use std::cell::Cell;

use platform_host::{Host, Unit};
use ratatui::Frame;

use super::{
    app::{App, Key, Tab},
    configuration::{Prompt, Then},
    home, service, status,
    ui::{frame, list::Scroll, logo::Header},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Screen {
    Home,
    Status,
    Service(Unit),
    Log(Unit),
    Maintenance,
    Maint(super::maint::Page),
    Help(Box<Screen>),
    Legacy,
    /// The first install (sub-project 3).
    Install(super::install::Stage),
}

#[derive(Clone, Debug)]
pub struct Nav {
    pub screen: Screen,
    /// Where Esc returns to: the screen, its highlighted row and its window.
    pub back: Vec<(Screen, usize, Scroll)>,
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
        self.back.push((from, self.row, self.scroll.get()));
        self.row = 0;
        self.scroll.set(Scroll::default());
    }

    /// Back one screen; false when there is nowhere to go.
    pub fn pop(&mut self) -> bool {
        let Some((previous, row, scroll)) = self.back.pop() else {
            return false;
        };
        self.screen = previous;
        self.row = row;
        self.scroll.set(scroll);
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
        Screen::Maint(page) => format!(" · Maintenance › {}", page.title()),
        Screen::Help(_) => " · Help".into(),
        Screen::Install(stage) => super::install::location(*stage),
        Screen::Legacy => match app.tab {
            Tab::Configuration => " · Maintenance › Settings files".into(),
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
        Screen::Install(stage) => super::install::draw(frame, &head, app, *stage),
        Screen::Home => home::draw(frame, &head, app),
        Screen::Maintenance => super::maint::draw_menu(frame, &head, app),
        Screen::Maint(page) => super::maint::draw(frame, &head, app, *page),
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
            Tab::Configuration => self.config.editing.is_none() && self.config.prompt.is_none(),
        }
    }

    pub(super) fn legacy_key(&mut self, key: Key) {
        match key {
            // q quits from Home only, but is typed into a value.
            Key::Char('q') if !self.typing() => {}
            Key::Esc if self.legacy_at_rest() => {
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
            Tab::Configuration => self.config.editing.is_some(),
        }
    }

    /// Back one screen; Home when there is none (a fresh install, finished).
    pub(super) fn back(&mut self) {
        self.message = None;
        if !self.nav.pop() {
            self.nav = Nav::new(Screen::Home);
        }
    }
}
