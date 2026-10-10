//! One service and its full log (spec §5): filled in Task 8.

use platform_host::{Host, Unit};
use ratatui::Frame;

use super::{
    app::{App, Key},
    ui::logo::Header,
};

pub fn draw<H: Host>(_frame: &mut Frame, _head: &Header, _app: &App<H>, _unit: Unit) {}

pub fn draw_log<H: Host>(_frame: &mut Frame, _head: &Header, _app: &App<H>, _unit: Unit) {}

impl<H: Host> App<H> {
    pub(super) fn service_key(&mut self, _unit: Unit, _key: Key) {}

    pub(super) fn log_key(&mut self, _key: Key) {}
}
