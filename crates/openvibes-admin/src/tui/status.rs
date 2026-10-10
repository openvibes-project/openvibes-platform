//! The Status screen (spec §4): filled in Task 7.

use platform_host::Host;
use ratatui::Frame;

use super::{
    app::{App, Key},
    ui::logo::Header,
};

pub fn draw<H: Host>(_frame: &mut Frame, _head: &Header, _app: &App<H>) {}

impl<H: Host> App<H> {
    pub(super) fn status_key(&mut self, _key: Key) {}
}
