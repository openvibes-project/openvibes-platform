//! Where the operator is (spec §3): a stack of screens. Enter opens, Esc
//! pops (back to the row and window it left), ? opens Help, q quits from
//! Home. The install has its own screens (`install`).

use std::cell::Cell;

use platform_host::{Host, Unit};
use ratatui::Frame;

use super::{
    app::App,
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
    /// The appliance's System page.
    System,
    /// System › Network.
    Network,
    /// System › Time.
    Time,
    /// System › SSH.
    Ssh,
    Help(Box<Screen>),
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
        Screen::System => " · System".into(),
        Screen::Network => " · System › Network".into(),
        Screen::Time => " · System › Time".into(),
        Screen::Ssh => " · System › SSH".into(),
        Screen::Maint(page) => format!(" · Maintenance › {}", page.title()),
        Screen::Help(_) => " · Help".into(),
        Screen::Install(stage) => {
            let at = super::install::location(*stage);
            // Replace and Console open the install's screens as they are.
            let from = |page| {
                let page = Screen::Maint(page);
                app.nav.back.iter().any(|(screen, ..)| *screen == page)
            };
            let certs = " · Install › Certificates ›";
            if from(super::maint::Page::Replace) {
                at.replace(certs, " · Maintenance › Certificates › Replace ›")
            } else if from(super::maint::Page::ConsoleUse) {
                at.replace(certs, " · Maintenance › Certificates › Console ›")
            } else {
                at
            }
        }
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
        Screen::Install(stage) => super::install::draw(frame, &head, app, *stage),
        Screen::Home => home::draw(frame, &head, app),
        Screen::Maintenance => super::maint::draw_menu(frame, &head, app),
        Screen::Maint(page) => super::maint::draw(frame, &head, app, *page),
        Screen::System => super::system::draw(frame, &head, app),
        Screen::Network => super::network::draw(frame, &head, app),
        Screen::Time => super::time::draw(frame, &head, app),
        Screen::Ssh => super::ssh::draw(frame, &head, app),
        Screen::Status => status::draw(frame, &head, app),
        Screen::Service(unit) => service::draw(frame, &head, app, *unit),
        Screen::Log(unit) => service::draw_log(frame, &head, app, *unit),
        Screen::Help(from) => home::draw_help(frame, &head, app, from),
    }
}

impl<H: Host> App<H> {
    /// Back one screen; Home when there is none (a fresh install, finished).
    pub(super) fn back(&mut self) {
        self.message = None;
        if !self.nav.pop() {
            self.nav = Nav::new(Screen::Home);
        }
        self.home_health();
    }
}
