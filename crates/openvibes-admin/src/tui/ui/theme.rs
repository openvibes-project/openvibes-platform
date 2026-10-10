//! Colours, styles and glyphs every screen shares. Colour follows
//! no-color.org (`NO_COLOR` set and not empty: none); bold, dim and
//! reversed stay, so a highlight is still visible without colour.

use std::ffi::OsStr;

use ratatui::style::{Color, Modifier, Style};

/// The brand teal (middle of the brand gradient).
pub const TEAL: Color = Color::Rgb(0x36, 0xb9, 0xe0);
const HIGHLIGHT: Color = Color::Rgb(0x1f, 0x3a, 0x4a);
const KEY: Color = Color::Rgb(0x30, 0x36, 0x3d);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Theme {
    pub color: bool,
    /// The Linux text console has no ⭡⭣ glyphs: plain arrows there.
    pub plain_arrows: bool,
}

impl Theme {
    pub fn from_env() -> Self {
        Self::new(std::env::var_os("NO_COLOR").as_deref(), std::env::var("TERM").ok().as_deref())
    }

    pub fn new(no_color: Option<&OsStr>, term: Option<&str>) -> Self {
        Self {
            color: no_color.is_none_or(OsStr::is_empty),
            plain_arrows: term == Some("linux"),
        }
    }

    fn fg(&self, color: Color) -> Style {
        if self.color { Style::new().fg(color) } else { Style::new() }
    }

    pub fn white(&self) -> Style {
        self.fg(Color::White).add_modifier(Modifier::BOLD)
    }
    pub fn teal(&self) -> Style {
        self.fg(TEAL).add_modifier(Modifier::BOLD)
    }
    /// The header rule and box lines.
    pub fn rule(&self) -> Style {
        self.fg(TEAL)
    }
    pub fn dim(&self) -> Style {
        Style::new().add_modifier(Modifier::DIM)
    }
    pub fn bold(&self) -> Style {
        Style::new().add_modifier(Modifier::BOLD)
    }
    pub fn green(&self) -> Style {
        self.fg(Color::Green)
    }
    pub fn yellow(&self) -> Style {
        self.fg(Color::Yellow)
    }
    pub fn red(&self) -> Style {
        self.fg(Color::Red)
    }
    /// The highlighted row.
    pub fn highlight(&self) -> Style {
        if self.color {
            Style::new().bg(HIGHLIGHT).fg(Color::White)
        } else {
            Style::new().add_modifier(Modifier::REVERSED)
        }
    }
    /// A key shown as a button.
    pub fn key(&self) -> Style {
        if self.color {
            Style::new().bg(KEY).fg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        }
    }

    pub fn up_down(&self) -> &'static str {
        if self.plain_arrows { "↑↓" } else { "⭡⭣" }
    }
    pub fn left_right(&self) -> &'static str {
        if self.plain_arrows { "←→" } else { "⭠⭢" }
    }
    pub fn up(&self) -> &'static str {
        if self.plain_arrows { "↑" } else { "⭡" }
    }
    pub fn down(&self) -> &'static str {
        if self.plain_arrows { "↓" } else { "⭣" }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use ratatui::style::{Color, Modifier};

    use super::*;

    #[test]
    fn arrows_are_plain_on_the_linux_console() {
        let fancy = Theme::new(None, Some("xterm-256color"));
        assert_eq!((fancy.up_down(), fancy.left_right()), ("⭡⭣", "⭠⭢"));
        let console = Theme::new(None, Some("linux"));
        assert_eq!((console.up_down(), console.left_right(), console.up(), console.down()), ("↑↓", "←→", "↑", "↓"));
    }

    #[test]
    fn no_color_keeps_highlight_and_keys_visible_without_colour() {
        let plain = Theme::new(Some(OsStr::new("1")), Some("xterm"));
        assert!(!plain.color);
        assert_eq!(plain.highlight().bg, None);
        assert!(plain.highlight().add_modifier.contains(Modifier::REVERSED));
        assert!(plain.key().add_modifier.contains(Modifier::REVERSED));
        assert_eq!(plain.teal().fg, None);
        let coloured = Theme::new(Some(OsStr::new("")), None);
        assert!(coloured.color, "an empty NO_COLOR means colour (no-color.org)");
        assert_eq!(coloured.teal().fg, Some(TEAL));
        assert_eq!(coloured.highlight().bg, Some(Color::Rgb(0x1f, 0x3a, 0x4a)));
    }
}
